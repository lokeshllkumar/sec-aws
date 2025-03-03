# sec-aws

An AI-powered security audit and remediation tool for AWS environments. It sscans AWS resources, identifies misconfigurations and security issues, and provides intelligent remediation steps using RAG.

## Features

- AWS Security Auditing - Detects misconfigurations and security risks.
- Multi-Service Scanning - Suports S3, EC2, and IAM.
- AI-Powered Fixes - Uses OpenAI's *gpt-4o-mini* model to suggest fixes for vulnerabilites.
- Pinecone Integration - Retrieves past fixes to improve aI suggestions.
- Simple CLI Interface - Easy-to-use commands for scanning and fixing security issues via a light-weight interface.

## Getting Started

- Prerequisties
    - Go 1.20+
    - Python3
    - AWS CLI (configured with credentials)
    - Docker (to containerize and isolate the application)
    - Pinecone (create an index to store vectors of relevant service data)

- Clone the Repository

```bash
git clone https://github.com/lokeshllkumar/sec-aws.git
cd sec-aws
```

- Install the required dependencies

```bash
go mod tidy
```

- Build the Project

```bash
go build -o sec-aws .
pip install -r server/requirements.txt
```

- Start the FastAPI server that generates vector embeddings and responses from the OpenAI API

```bash
python3 -u "server/main.py"
```

- Create a Pinecone index that will store vectors corresponding to relevant AWS service security vulnerability data

- Create a ```.env``` file that will store the following
```bash
AWS_ACCESS_KEY_ID=<your-aws-access-key>
AWS_SECRET_ACCESS_KEY=<your-aws-secret-access-key>
AWS_REGION=<you-preferred-aws-region>
OPENAI_API_KEY=<your-openai-api-key>
PINECONE_API_KEY=<your-pinecone-index-api-key>
PINECONE_INDEX_HOST=<your-pinecone-index-host>
```

- To deploy vulnerable resources (for testing),
    - Navigate into the ```terraform``` subdirectory containing the Terraform configuration files
    ```bash
    cd terraform
    ```

    - Initalize the Terraform backend, modules and its provider plugins
    ```bash
    terraform init
    ```

    - Preview the plan
    ```bash
    terraform plan
    ```


    - Deploy the reosurces
    ```bash
    terraform apply -auto-approve
    ```

- Run the CLI App

```bash
./sec-aws
```

## Usage

### Auditing

To audit security vulnerabilities in the resources, the ```audit``` subcommand is used:

- To scan all services
```bash
./sec-aws audit --all
```

- To scan a specific a service
```bash
./sec-aws audit --service <service-name>
```

### Fixing

To generate fix suggestions for all identified vulnerabilites, the ```fix``` subcommand is used:

```bash
./sec-aws fix
```
 
## To-Do

- [ ] must be able to fix specific resources using their unique names/IDs
- [ ] automate the remdiation of EC2 instances by modifying the resource properties
- [ ] write Terraform scripts to provision vulnerable resources ford demonstration
