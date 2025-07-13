FROM neo4j:5.15-community

# Basic authentication and database settings
ENV NEO4J_AUTH=neo4j/password123
ENV NEO4J_ACCEPT_LICENSE_AGREEMENT=yes
# Use current (non-deprecated) configuration names
ENV NEO4J_server_http_listen__address=0.0.0.0:7474
ENV NEO4J_server_bolt_listen__address=0.0.0.0:7687
ENV NEO4J_initial_dbms_default__database=authdata
# Increase memory settings
ENV NEO4J_server_memory_heap_max_size=12G
ENV NEO4J_dbms_memory_transaction_total_max=12G
# Enable APOC plugin
ENV NEO4J_PLUGINS=["apoc"]
ENV NEO4J_dbms_security_procedures_unrestricted=apoc.*
# Disable strict validation to allow for any minor config issues
ENV NEO4J_server_config_strict__validation_enabled=false

# Switch to root for installing additional packages
USER root

# Install curl and other dependencies for Ollama
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Create import directory
RUN mkdir -p /var/lib/neo4j/import
RUN chown -R neo4j:neo4j /var/lib/neo4j/import

# Copy import script
COPY import_data.cypher /var/lib/neo4j/import/
COPY wait_and_import.sh /var/lib/neo4j/
RUN chmod +x /var/lib/neo4j/wait_and_import.sh
RUN chown neo4j:neo4j /var/lib/neo4j/wait_and_import.sh

# Copy your existing docker-entrypoint.sh
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Copy our new simple entrypoint
COPY ollama-entrypoint.sh /ollama-entrypoint.sh
RUN chmod +x /ollama-entrypoint.sh

# Switch back to neo4j user
USER neo4j

# Expose ports (Neo4j: 7474, 7687; Ollama: 11434)
EXPOSE 7474 7687 11434

# Use our simple entrypoint
ENTRYPOINT ["/ollama-entrypoint.sh"]