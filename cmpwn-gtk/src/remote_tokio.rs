use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::prelude::*;
use std::thread;
use std::pin::Pin;
use std::future::Future;
use std::any::Any;
use once_cell::sync::Lazy;

static REMOTE_TOKIO: Lazy<RemoteTokio> = Lazy::new(|| RemoteTokio::new());

pub async fn run<F>(future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static
{
    REMOTE_TOKIO.run(future).await
}

pub fn init() {
    Lazy::force(&REMOTE_TOKIO);
}

#[derive(Clone)]
pub struct RemoteTokio {
    send_task: mpsc::UnboundedSender<SpawnTokioFuture>,
}

struct SpawnTokioFuture {
    future: Pin<Box<dyn Future<Output = Box<dyn Any + Send>> + Send>>,
    answer_box: oneshot::Sender<Box<dyn Any + Send>>
}

impl RemoteTokio {
    pub fn new() -> RemoteTokio {
        let (sender, mut receiver) = mpsc::unbounded();
        let _tokio_rt = thread::spawn(move || {
            let mut rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                while let Some(SpawnTokioFuture { future, answer_box }) = receiver.next().await {
                    tokio::spawn(async move {
                        // TODO: catch_panic, and propagate it.
                        let _ = answer_box.send(future.await);
                    });
                }
            })
        });

        RemoteTokio {
            send_task: sender,
        }
    }

    pub async fn run<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static
    {
        let (answer_send, answer_recv) = oneshot::channel();
        let msg = SpawnTokioFuture {
            future: Box::pin(async {
                let ret = future.await;
                Box::new(ret) as Box<dyn Any + Send>
            }),
            answer_box: answer_send
        };
        (&self.send_task).unbounded_send(msg).expect("Remote tokio to still be alive.");
        *Box::<dyn Any>::downcast(answer_recv.await.unwrap())
            .expect("Future result type to match expectation.")
    }
}