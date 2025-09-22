use tonic::{transport::Server, Request, Response, Status};
use tonic_reflection::server::Builder as ReflectionBuilder;
use std::time::{SystemTime, UNIX_EPOCH};

// Import the generated protobuf code
pub mod content {
    tonic::include_proto!("content");
}

// Include the file descriptor set for reflection
pub mod content_descriptor {
    include!(concat!(env!("OUT_DIR"), "/content_descriptor.rs"));
}

use content::content_service_server::{ContentService, ContentServiceServer};
use content::{ContentRequest, ContentResponse};

#[derive(Default)]
pub struct ContentServiceImpl {}

#[tonic::async_trait]
impl ContentService for ContentServiceImpl {
    async fn get_content(
        &self,
        request: Request<ContentRequest>,
    ) -> Result<Response<ContentResponse>, Status> {
        let req = request.into_inner();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let response = ContentResponse {
            title: format!("Content for path: {}", req.path),
            body: "This is generic content served via gRPC".to_string(),
            status: "success".to_string(),
            timestamp,
        };

        Ok(Response::new(response))
    }

    async fn get_protected_content(
        &self,
        request: Request<ContentRequest>,
    ) -> Result<Response<ContentResponse>, Status> {
        let req = request.into_inner();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let response = ContentResponse {
            title: "This is Protected Content".to_string(),
            body: "This content requires L402 authentication".to_string(),
            status: "protected".to_string(),
            timestamp,
        };

        Ok(Response::new(response))
    }

    async fn get_free_content(
        &self,
        request: Request<ContentRequest>,
    ) -> Result<Response<ContentResponse>, Status> {
        let req = request.into_inner();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let response = ContentResponse {
            title: "Free Content".to_string(),
            body: "This content is freely accessible via gRPC".to_string(),
            status: "free".to_string(),
            timestamp,
        };

        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::]:50051".parse()?;
    let service = ContentServiceImpl::default();

    println!("gRPC server listening on {}", addr);

    let reflection_service = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(&content_descriptor::FILE_DESCRIPTOR_SET[..])
        .build()?;

    Server::builder()
        .add_service(ContentServiceServer::new(service))
        .add_service(reflection_service)
        .serve(addr)
        .await?;

    Ok(())
}
