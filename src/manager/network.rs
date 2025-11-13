use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn send_and_receive(target_ip: &str, packet: &[u8]) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind to local sockert")?;

    let target_address = format!("{}:161", target_ip);

    let _ = socket
        .connect(&target_address)
        .await
        .with_context(|| format!("Failed to connect to {} address", target_address));

    socket.send(packet).await.context("Failed to send packet")?;

    let mut response_buf = vec![0; 4096];
    let result = timeout(DEFAULT_TIMEOUT, socket.recv(&mut response_buf)).await;

    match result {
        Ok(Ok(len)) => {
            response_buf.truncate(len);
            Ok(response_buf)
        }
        Ok(Err(e)) => Err(anyhow!(e).context("Failed to receive data")),
        Err(_) => Err(anyhow!(
            "Timeout: No response from {} after {}s",
            target_address,
            DEFAULT_TIMEOUT.as_secs()
        )),
    }
}
