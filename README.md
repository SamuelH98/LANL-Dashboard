
# Analysis of the LANL Active Directory Cybersecurity Dataset

This project provides a complete framework for analyzing the Los Alamos National Laboratory (LANL) cybersecurity authentication dataset. It uses a multi-threaded C parser to process the raw logs, imports the data into a Neo4j graph database, and provides an interactive dashboard powered by a `Gemma` LLM agent for threat detection and analysis.

## Features

-   **High-Performance Preprocessing:** A multi-threaded C program to efficiently parse, filter, and label millions of log events.
-   **Graph-Based Data Model:** Leverages Neo4j to model complex relationships between users, computers, and authentication events.
-   **Interactive Analysis Dashboard:** Built with Gradio for real-time visualization of security metrics from the LANL logs.
-   **Agentic AI Analysis:** Deploys an LLM agent (Gemma-3 via LiteLLM) to perform autonomous security analysis, identify threats, and generate human-readable reports.
-   **System Status Monitoring:** The dashboard provides live status checks for backend services (Neo4j and Ollama).

## System Architecture

The framework consists of three main stages:

```
[Raw LANL .txt files] -> [C Preprocessor] -> [output.csv] -> [Neo4j Docker Container] <-> [Gradio/Python Backend] <-> [Ollama LLM Agent]
```

1.  **Preprocessing:** Raw log files are processed into a structured, labeled CSV.
2.  **Data Ingestion:** The CSV is imported into a Neo4j database using an optimized Cypher script.
3.  **Analysis & Visualization:** A Gradio web application queries Neo4j for visualizations and deploys an LLM agent to conduct deeper security analysis.

## Prerequisites

Before you begin, ensure you have the following installed and configured:

1.  **Docker & Docker Compose:** To run the Neo4j database.
2.  **C Compiler:** A C compiler like `gcc` to build the preprocessor.
3.  **Python 3.8+:** With `pip` for installing dependencies.
4.  **Ollama:** Installed and running. [Ollama Website](https://ollama.com/)
5.  **Gemma-3 Model:** Pull the required LLM model via Ollama.
    ```bash
    ollama pull gemma:1b
    ```
6.  **LANL Dataset:** Download `auth.txt` and `redteam.txt` into the project's root directory.

## Setup and Running the Application

Follow these steps to get the entire system running.


### 1. Compile and Run the Preprocessor

First, compile the C preprocessor. Then, run it to generate the `output.csv` file from the raw LANL data.

```bash
# Compile the preprocessor
gcc -o preprocessor preprocessor.c -lpthread

# Run the preprocessor (this may take several minutes)
./preprocessor auth.txt redteam.txt output.csv
```
This creates the `output.csv` file required by the Neo4j importer.

### 2. Start the Neo4j Database & Import Data

With `output.csv` present, use Docker Compose to build and run the Neo4j container. The container will automatically execute the `import_data.txt` script to create the graph.

```bash
docker-compose up --build
```
Or run in detached mode:
```bash
docker-compose up -d --build
```

View logs:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f python-app
docker-compose logs -f neo4j
docker-compose logs -f ollama
```

### 4. Install Python Dependencies

In a separate terminal, install the required Python packages for the frontend dashboard.

```bash
pip install -r requirements.txt
```

### 5. Launch the Gradio Dashboard

Once the dependencies are installed and the Neo4j container shows that it is ready, start the Gradio web application.

```bash
python src/main.py
```
You can now access the system via your web browser:

-   **Dashboard URL:** http://localhost:7860
-   **Neo4j Browser URL:** http://localhost:7474 (Username: `neo4j`, Password: `password123`)

## Frontend Dashboard

The interactive dashboard provides two main functions:

1.  **Security Visualizations:** A set of plots that give a high-level overview of the security posture, including:
    -   Authentication Success Rate
    -   Top 10 Most Active Users
    -   Potential Lateral Movement Risk
    -   Hourly Authentication Activity

2.  **Agentic Security Analysis:** An LLM-powered agent that can perform deeper analysis.
    -   Select an analysis type from the dropdown (e.g., "Comprehensive Analysis").
    -   Click "Run Analysis" to task the agent.
    -   The agent queries the database, analyzes the results, and provides findings, a list of suspicious activities, and recommendations in a structured report.

## Data Model (Event-Centric)

The import script creates an **event-centric** graph structure for optimal performance and analytical flexibility.

### Nodes:
-   `User`: Represents a user account (e.g., `U123@DOM1`).
-   `Computer`: Represents a host computer (e.g., `C12345`).
-   `AuthEvent`: Represents a single authentication event, containing all its properties (time, success, type, label, etc.).

### Relationships:
-   `(AuthEvent)-[:FROM_USER]->(User)`
-   `(AuthEvent)-[:TO_USER]->(User)`
-   `(AuthEvent)-[:FROM_COMPUTER]->(Computer)`
-   `(AuthEvent)-[:TO_COMPUTER]->(Computer)`

This model allows for complex traversals (e.g., finding a user who authenticated to a computer) by pivoting through the `AuthEvent` nodes.

## Optimized Cypher Queries

The following are sample queries optimized for the event-centric model, which can be run directly in the Neo4j Browser.

### Red Team Analysis
```cypher
// Find all red team events and their context
MATCH (a:AuthEvent)-[:FROM_USER]->(u:User),
      (a)-[:FROM_COMPUTER]->(sc:Computer),
      (a)-[:TO_COMPUTER]->(dc:Computer)
WHERE a.is_redteam = true
RETURN a.timestamp, u.name as user, sc.name as source_computer, dc.name as dest_computer, a.success
ORDER BY a.timestamp
LIMIT 100;
```

### Lateral Movement Detection
```cypher
// User u logs into c1, then from c1 to c2 within 1 hour
MATCH (u:User)<-[:FROM_USER]-(a1:AuthEvent)-[:TO_COMPUTER]->(c1:Computer),
      (c1)<-[:FROM_COMPUTER]-(a2:AuthEvent)-[:TO_COMPUTER]->(c2:Computer)
WHERE a2.time > a1.time AND (a2.time - a1.time) <= 3600
  AND id(c1) <> id(c2)
  AND (a2)-[:FROM_USER]->(u)
RETURN u.name, c1.name as intermediate_computer, c2.name as target_computer,
       duration.between(a1.timestamp, a2.timestamp) as time_difference
ORDER BY time_difference
LIMIT 100;
```

### High-Frequency Failed Logins
```cypher
// Find users with a high number of failed authentications to specific computers
MATCH (u:User)<-[:FROM_USER]-(a:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
WHERE a.success = 'Failure'
RETURN u.name, c.name, count(a) as failed_attempts
ORDER BY failed_attempts DESC
LIMIT 20;
```

## Troubleshooting

-   **Neo4j Import Issues:** Check the Docker logs (`docker-compose logs -f neo4j-auth-data`) for errors. Ensure `output.csv` exists and is not empty. The import can take 10-20 minutes depending on your hardware.
-   **Agent Not Responding:** Ensure the Ollama server is running and the `gemma:2b` model is available (`ollama list`). Check the `agent.py` terminal output for connection errors.
-   **Memory Issues:** For larger datasets, you may need to increase the memory allocated to the Neo4j container in `docker-compose.yml`.

## Data Cleanup

To completely reset the database and re-import the data:
```bash
docker-compose down -v
```
The `-v` flag is critical as it removes the Neo4j data volume. After running this, you can start fresh with `docker-compose up --build`.

