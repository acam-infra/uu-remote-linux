//! Message27/SYN JSON follows src/port_mapping.rs; TCP half-close is unsupported.
use super::*;
use std::{collections::HashMap,sync::atomic::{AtomicU64,Ordering}};
use tokio::{net::{TcpListener,TcpStream},io::{AsyncReadExt,AsyncWriteExt},sync::watch};
#[derive(Clone,Debug)]
pub struct Status {pub id:u64,pub name:String,pub local_port:u16,pub streams:usize,pub failures:u64}
struct Rule {status:Arc<Mutex<Status>>,stop:watch::Sender<bool>,task:tokio::task::JoinHandle<()>}
type Routes=Arc<Mutex<HashMap<(u64,u64),mpsc::UnboundedSender<(u64,Vec<u8>)>>>>;
pub struct PortMap {io:Transport,session:u64,next:Arc<AtomicU64>,routes:Routes,rules:Mutex<HashMap<u64,Rule>>,alive:watch::Receiver<()>,worker:tokio::task::JoinHandle<()>}
pub(crate) const PORTMAP_CHUNK:usize=32*1024;
pub fn frame(session:u64,rule:u64,stream:u64,kind:u64,payload:&[u8])->Vec<u8>{
    let mut b=Vec::with_capacity(payload.len()+48);
    for (n,v) in [(1,session),(2,rule),(3,stream),(4,kind)] {wire::int(n,v,&mut b);}
    wire::bytes(5,payload,&mut b);
    wire::envelope(0,27,&b)
}
struct Route {routes:Routes,key:(u64,u64),status:Arc<Mutex<Status>>}
impl Drop for Route {fn drop(&mut self){self.routes.lock().unwrap().remove(&self.key);self.status.lock().unwrap().streams-=1;}}
impl Drop for PortMap {fn drop(&mut self){self.worker.abort();for(_,r)in self.rules.lock().unwrap().drain(){let _=r.stop.send(true);}self.routes.lock().unwrap().clear();}}
impl PortMap {
    pub fn new(io:Transport,mut rx:mpsc::Receiver<Packet>)->Self{
        let session=1u64;let routes:Routes=Arc::new(Mutex::new(HashMap::new()));let route=routes.clone();
        let(life,alive)=watch::channel(());
        let worker=tokio::spawn(async move{
            let _life=life;
            while let Some((channel,b))=rx.recv().await {
                if channel!=FILE{continue}let Some(f)=blob(&b,27)else{continue};
                let key=(uint(f,2),uint(f,3));let sender=route.lock().unwrap().get(&key).cloned();
                if uint(f,1)!=session || sender.is_none() {
                    let kinds=crate::protocol::decode_wire(f).map(|x|x.iter().map(|w|(w.number,match w.value{crate::protocol::WireValue::Varint(_)=>"varint",crate::protocol::WireValue::Bytes(_)=>"bytes",_=>"fixed"})).collect::<Vec<_>>()).unwrap_or_default();
                    log::warn!("Port mapping frame unmatched: fields={kinds:?} session_match={} route_match={} type={}",uint(f,1)==session,sender.is_some(),uint(f,4));
                    continue;
                }
                if let Some(tx)=sender {if tx.send((uint(f,4),blob(f,5).unwrap_or_default().to_vec())).is_err(){route.lock().unwrap().remove(&key);}}
            }
            route.lock().unwrap().clear();
        });
        Self{io,session,next:Arc::new(AtomicU64::new(1)),routes,rules:Mutex::new(HashMap::new()),alive,worker}
    }
    pub async fn closed(&self){let mut alive=self.alive.clone();let _=alive.changed().await;}
    pub fn status(&self)->Vec<Status>{self.rules.lock().unwrap().values().map(|r|r.status.lock().unwrap().clone()).collect()}
    pub async fn add_rule(&self,name:impl Into<String>,local_port:u16,target_host:impl Into<String>,target_port:u16)->Result<u64,String>{
        if self.worker.is_finished(){return Err("Forwarding transport closed".into())}
        let host=target_host.into();if host.trim().is_empty() || target_port==0 {return Err("Invalid forwarding target".into())}
        let listener=TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,local_port)).await.map_err(|_|"Cannot bind local forwarding port")?;
        let port=listener.local_addr().map_err(|_|"Cannot inspect local forwarding port")?.port();
        let id=self.next.fetch_add(1,Ordering::Relaxed);let status=Arc::new(Mutex::new(Status{id,name:name.into(),local_port:port,streams:0,failures:0}));
        let(stopper,mut stop)=watch::channel(false);let st=status.clone();let io=self.io.clone();let routes=self.routes.clone();let next=self.next.clone();let session=self.session;
        let mut disconnected=self.alive.clone();
        let task=tokio::spawn(async move {
            let mut streams=tokio::task::JoinSet::new();
            loop {tokio::select!{
                _=stop.changed()=>break,
                _=disconnected.changed()=>break,
                _=streams.join_next(),if !streams.is_empty()=>{},
                accepted=listener.accept()=>{
                    let Ok((socket,_))=accepted else{break};
                    let _ = socket.set_nodelay(true);
                    if st.lock().unwrap().streams>=128 {continue}
                    let stream=next.fetch_add(1,Ordering::Relaxed);let(tx,rx)=mpsc::unbounded_channel();
                    routes.lock().unwrap().insert((id,stream),tx);st.lock().unwrap().streams+=1;
                    let guard=Route{routes:routes.clone(),key:(id,stream),status:st.clone()};
                    let io=io.clone();let host=host.clone();let mut cancel=stop.clone();let mut transport_closed=disconnected.clone();
                    streams.spawn(async move {
                        let result=tokio::select!{r=forward(&io,session,id,stream,socket,rx,&host,target_port)=>r,_=cancel.changed()=>Ok(()),_=transport_closed.changed()=>Err("Forwarding transport closed".into())};
                        if let Err(reason)=&result{guard.status.lock().unwrap().failures+=1;log::warn!("Port mapping stream ended: {reason}");}
                        let _=io.send(FILE,frame(session,id,stream,1,&[])).await;drop(guard);
                    });
                }
            }}
            drop(listener);
            while streams.join_next().await.is_some(){}
        });
        self.rules.lock().unwrap().insert(id,Rule{status,stop:stopper,task});Ok(id)
    }
    pub async fn remove_rule(&self,id:u64)->Result<(),String>{
        let rule=self.rules.lock().unwrap().remove(&id).ok_or("Unknown forwarding rule")?;
        let _=rule.stop.send(true);let mut task=rule.task;
        if tokio::time::timeout(TIMEOUT+Duration::from_secs(1),&mut task).await.is_err(){task.abort();return Err("Forwarding shutdown timed out".into())}Ok(())
    }
}
async fn forward(io:&Transport,session:u64,rule:u64,stream:u64,socket:TcpStream,mut rx:mpsc::UnboundedReceiver<(u64,Vec<u8>)>,host:&str,port:u16)->Result<(),String>{
    let syn=serde_json::json!({"version":1,"target_host":host,"target_port":port}).to_string();
    io.send(FILE,frame(session,rule,stream,0,syn.as_bytes())).await?;
    let ack=tokio::time::timeout(Duration::from_secs(12),rx.recv()).await.map_err(|_|"Forwarding SYN timeout")?.ok_or("Forwarding channel closed")?;
    if ack.0!=3 {return Err(format!("Forwarding SYN answered with frame type {}",ack.0))}
    if serde_json::from_slice::<serde_json::Value>(&ack.1).ok().and_then(|v|v["ok"].as_bool())!=Some(true){return Err("Forwarding target rejected".into())}
    let (mut rd, mut wr) = socket.into_split();
    let up = async {
        let mut buf=vec![0u8;PORTMAP_CHUNK];
        loop {
            let n=rd.read(&mut buf).await.map_err(|_|"Forwarding read failed".to_string())?;
            if n==0 {break}
            io.send(FILE,frame(session,rule,stream,2,&buf[..n])).await?;
        }
        Ok::<(),String>(())
    };
    let down = async {
        while let Some(f)=rx.recv().await {
            match f {
                (2,b)=>if wr.write_all(&b).await.is_err(){break},
                (1,_)=>break,
                (4,_)=>{},
                _=>return Err("Unexpected forwarding frame".into()),
            }
        }
        Ok::<(),String>(())
    };
    let res = tokio::select!{ r=up=>r, r=down=>r };
    let _=wr.shutdown().await;
    res
}

pub async fn run_stdio(io:Transport,mut rx:mpsc::Receiver<Packet>,host:&str,port:u16)->Result<(),String>{
    if host.trim().is_empty() || port==0 {return Err("Invalid forwarding target".into())}
    let session=1u64;let rule=1u64;let stream=1u64;
    let (tx,mut stream_rx)=mpsc::unbounded_channel::<(u64,Vec<u8>)>();
    let worker=tokio::spawn(async move{
        while let Some((channel,b))=rx.recv().await {
            if channel!=FILE{continue}
            let Some(f)=blob(&b,27)else{continue};
            if uint(f,1)!=session || uint(f,2)!=rule || uint(f,3)!=stream {continue}
            let kind=uint(f,4);
            let payload=blob(f,5).unwrap_or_default().to_vec();
            if tx.send((kind,payload)).is_err(){break}
        }
    });
    let syn=serde_json::json!({"version":1,"target_host":host,"target_port":port}).to_string();
    io.send(FILE,frame(session,rule,stream,0,syn.as_bytes())).await?;
    let ack=tokio::time::timeout(Duration::from_secs(15),stream_rx.recv()).await.map_err(|_|"Forwarding SYN timeout")?.ok_or("Forwarding channel closed")?;
    if ack.0!=3 {worker.abort();return Err(format!("Forwarding SYN answered with frame type {}",ack.0))}
    if serde_json::from_slice::<serde_json::Value>(&ack.1).ok().and_then(|v|v["ok"].as_bool())!=Some(true){worker.abort();return Err("Forwarding target rejected".into())}
    let up = async {
        let mut stdin=tokio::io::stdin();
        let mut buf=vec![0u8;PORTMAP_CHUNK];
        loop {
            let n=match stdin.read(&mut buf).await {Ok(n)=>n,Err(_)=>break};
            if n==0 {break}
            if io.send(FILE,frame(session,rule,stream,2,&buf[..n])).await.is_err(){break}
        }
        Ok::<(),String>(())
    };
    let down = async {
        let mut stdout=tokio::io::stdout();
        while let Some(first)=stream_rx.recv().await {
            let mut batch=vec![first];
            while let Ok(next)=stream_rx.try_recv() {
                batch.push(next);
                if batch.len()>=32 {break}
            }
            let mut should_close=false;
            for f in batch {
                match f {
                    (2,b)=>{ if stdout.write_all(&b).await.is_err(){should_close=true;break} }
                    (1,_)=>{ should_close=true; break; }
                    (4,_)=>{}
                    _=>return Err("Unexpected forwarding frame".into()),
                }
            }
            if stdout.flush().await.is_err() || should_close {break}
        }
        Ok::<(),String>(())
    };
    let res = tokio::select!{ r=up=>r, r=down=>r };
    let _=io.send(FILE,frame(session,rule,stream,1,&[])).await;
    worker.abort();
    res
}
