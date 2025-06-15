FROM neo4j:5.15-community

# Set environment variables
ENV NEO4J_AUTH=neo4j/password123
ENV NEO4J_dbms_default__database=authdata
ENV NEO4J_dbms_memory_heap_initial__size=2G
ENV NEO4J_dbms_memory_heap_max__size=8G
ENV NEO4J_dbms_memory_pagecache_size=4G
ENV NEO4J_dbms_memory_transaction_total_max=12G
ENV NEO4J_dbms_connector_bolt_listen__address=0.0.0.0:7687
ENV NEO4J_dbms_connector_http_listen__address=0.0.0.0:7474
ENV NEO4J_ACCEPT_LICENSE_AGREEMENT=yes

# Enable APOC plugin
ENV NEO4J_PLUGINS=["apoc"]
ENV NEO4J_dbms_security_procedures_unrestricted=apoc.*

# Create import directory
USER root
RUN mkdir -p /var/lib/neo4j/import
RUN chown -R neo4j:neo4j /var/lib/neo4j/import

# Copy import script
COPY import_data.cypher /var/lib/neo4j/import/
COPY wait_and_import.sh /var/lib/neo4j/
RUN chmod +x /var/lib/neo4j/wait_and_import.sh
RUN chown neo4j:neo4j /var/lib/neo4j/wait_and_import.sh

USER neo4j

# Expose ports
EXPOSE 7474 7687

# Custom entrypoint that starts Neo4j and then imports data
COPY docker-entrypoint.sh /docker-entrypoint.sh
USER root
RUN chmod +x /docker-entrypoint.sh
USER neo4j

ENTRYPOINT ["/docker-entrypoint.sh"]
