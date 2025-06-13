#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

#define MAX_LINE_LENGTH 1024
#define CHUNK_SIZE 1000000  // Process 1M lines at a time
#define NUM_THREADS 15
#define MAX_REDTEAM_EVENTS 100000

// Structure to hold authentication data
typedef struct {
    int time;
    char source_user[256];
    char dest_user[256];
    char source_computer[256];
    char dest_computer[256];
    char auth_type[64];
    char logon_type[64];
    char auth_orientation[64];
    char success[16];
} auth_event_t;

// Structure to hold red team data
typedef struct {
    int time;
    char user[256];
    char source_computer[256];
    char dest_computer[256];
} redteam_event_t;

// Thread data structure
typedef struct {
    auth_event_t *auth_events;
    int start_idx;
    int end_idx;
    redteam_event_t *redteam_events;
    int redteam_count;
    FILE *output_file;
    pthread_mutex_t *file_mutex;
    int thread_id;
    int *total_matches;
    pthread_mutex_t *match_mutex;
} thread_data_t;

// Global variables
static redteam_event_t redteam_events[MAX_REDTEAM_EVENTS];
static int redteam_count = 0;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t match_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to trim whitespace
char* trim(char* str) {
    char *end;
    while(*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') str++;
    if(*str == 0) return str;
    end = str + strlen(str) - 1;
    while(end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    end[1] = '\0';
    return str;
}

// Function to check if line contains question mark
int contains_question_mark(const char* line) {
    return strchr(line, '?') != NULL;
}

// Function to parse authentication line
int parse_auth_line(char* line, auth_event_t* event) {
    // Skip lines containing question marks
    if (contains_question_mark(line)) {
        return 0;
    }
    
    char* token;
    char* line_copy = strdup(line);
    int field = 0;
    
    token = strtok(line_copy, ",");
    while (token != NULL && field < 9) {
        token = trim(token);
        
        switch(field) {
            case 0: event->time = atoi(token); break;
            case 1: strncpy(event->source_user, token, 255); event->source_user[255] = '\0'; break;
            case 2: strncpy(event->dest_user, token, 255); event->dest_user[255] = '\0'; break;
            case 3: strncpy(event->source_computer, token, 255); event->source_computer[255] = '\0'; break;
            case 4: strncpy(event->dest_computer, token, 255); event->dest_computer[255] = '\0'; break;
            case 5: strncpy(event->auth_type, token, 63); event->auth_type[63] = '\0'; break;
            case 6: strncpy(event->logon_type, token, 63); event->logon_type[63] = '\0'; break;
            case 7: strncpy(event->auth_orientation, token, 63); event->auth_orientation[63] = '\0'; break;
            case 8: strncpy(event->success, token, 15); event->success[15] = '\0'; break;
        }
        
        token = strtok(NULL, ",");
        field++;
    }
    
    free(line_copy);
    return (field == 9) ? 1 : 0;
}

// Function to parse red team line
int parse_redteam_line(char* line, redteam_event_t* event) {
    // Skip lines containing question marks
    if (contains_question_mark(line)) {
        return 0;
    }
    
    char* token;
    char* line_copy = strdup(line);
    int field = 0;
    
    token = strtok(line_copy, ",");
    while (token != NULL && field < 4) {
        token = trim(token);
        
        switch(field) {
            case 0: event->time = atoi(token); break;
            case 1: strncpy(event->user, token, 255); event->user[255] = '\0'; break;
            case 2: strncpy(event->source_computer, token, 255); event->source_computer[255] = '\0'; break;
            case 3: strncpy(event->dest_computer, token, 255); event->dest_computer[255] = '\0'; break;
        }
        
        token = strtok(NULL, ",");
        field++;
    }
    
    free(line_copy);
    return (field == 4) ? 1 : 0;
}

// Function to check if an auth event matches a red team event
int is_redteam_event(auth_event_t* auth, redteam_event_t* redteam_events, int redteam_count) {
    for (int i = 0; i < redteam_count; i++) {
        // Check time match (exact match required)
        if (auth->time != redteam_events[i].time) {
            continue;
        }
        
        // Case 1: Direct match - redteam user is the source user in auth event
        if (strcmp(auth->source_user, redteam_events[i].user) == 0 &&
            strcmp(auth->source_computer, redteam_events[i].source_computer) == 0 &&
            strcmp(auth->dest_computer, redteam_events[i].dest_computer) == 0) {
            return 1;
        }
        
        // Case 2: Reverse match - redteam user is the destination user in auth event
        if (strcmp(auth->dest_user, redteam_events[i].user) == 0 &&
            strcmp(auth->dest_computer, redteam_events[i].source_computer) == 0 &&
            strcmp(auth->source_computer, redteam_events[i].dest_computer) == 0) {
            return 1;
        }
        
        // Case 3: Lateral movement - user authenticates TO a machine
        if (strcmp(auth->source_user, redteam_events[i].user) == 0 &&
            strcmp(auth->dest_computer, redteam_events[i].dest_computer) == 0) {
            if (strcmp(auth->source_computer, redteam_events[i].source_computer) == 0) {
                return 1;
            }
        }
        
        // Case 4: Time and computer match with user involved
        if ((strcmp(auth->source_computer, redteam_events[i].source_computer) == 0 &&
             strcmp(auth->dest_computer, redteam_events[i].dest_computer) == 0) ||
            (strcmp(auth->source_computer, redteam_events[i].dest_computer) == 0 &&
             strcmp(auth->dest_computer, redteam_events[i].source_computer) == 0)) {
            
            if (strcmp(auth->source_user, redteam_events[i].user) == 0 ||
                strcmp(auth->dest_user, redteam_events[i].user) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

// Thread worker function
void* process_auth_events(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    char output_line[2048];
    int processed = 0;
    int matches_found = 0;
    
    for (int i = data->start_idx; i < data->end_idx; i++) {
        auth_event_t* event = &data->auth_events[i];
        
        int is_redteam = is_redteam_event(event, data->redteam_events, data->redteam_count);
        if (is_redteam) {
            matches_found++;
        }
        
        // Create feature string for BERT training
        snprintf(output_line, sizeof(output_line), 
                "\"%d,%s,%s,%s,%s,%s,%s,%s,%s\",%d\n",
                event->time,
                event->source_user,
                event->dest_user,
                event->source_computer,
                event->dest_computer,
                event->auth_type,
                event->logon_type,
                event->auth_orientation,
                event->success,
                is_redteam);
        
        // Write to output file (thread-safe)
        pthread_mutex_lock(data->file_mutex);
        fprintf(data->output_file, "%s", output_line);
        pthread_mutex_unlock(data->file_mutex);
        
        processed++;
    }
    
    // Update global match counter
    pthread_mutex_lock(data->match_mutex);
    *(data->total_matches) += matches_found;
    pthread_mutex_unlock(data->match_mutex);
    
    return NULL;
}

// Function to load red team events
int load_redteam_events(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error: Cannot open redteam file %s: %s\n", filename, strerror(errno));
        return 0;
    }
    
    char line[MAX_LINE_LENGTH];
    redteam_count = 0;
    int skipped_lines = 0;
    
    printf("Loading red team events from %s...\n", filename);
    
    while (fgets(line, sizeof(line), file) && redteam_count < MAX_REDTEAM_EVENTS) {
        if (strlen(line) > 1) {  // Skip empty lines
            if (contains_question_mark(line)) {
                skipped_lines++;
                continue;
            }
            if (parse_redteam_line(line, &redteam_events[redteam_count])) {
                redteam_count++;
            }
        }
    }
    
    fclose(file);
    printf("Loaded %d red team events\n", redteam_count);
    if (skipped_lines > 0) {
        printf("Skipped %d lines containing '?' characters\n", skipped_lines);
    }
    return redteam_count;
}

// Function to process a chunk of authentication events
int process_chunk(auth_event_t* chunk, int chunk_size, FILE* output_file, int* total_matches) {
    // Create threads for processing this chunk
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    int events_per_thread = chunk_size / NUM_THREADS;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].auth_events = chunk;
        thread_data[i].start_idx = i * events_per_thread;
        thread_data[i].end_idx = (i == NUM_THREADS - 1) ? chunk_size : (i + 1) * events_per_thread;
        thread_data[i].redteam_events = redteam_events;
        thread_data[i].redteam_count = redteam_count;
        thread_data[i].output_file = output_file;
        thread_data[i].file_mutex = &file_mutex;
        thread_data[i].thread_id = i;
        thread_data[i].total_matches = total_matches;
        thread_data[i].match_mutex = &match_mutex;
        
        if (pthread_create(&threads[i], NULL, process_auth_events, &thread_data[i]) != 0) {
            printf("Error creating thread %d\n", i);
            return 0;
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    return 1;
}

// Main function to process authentication file in chunks
int process_auth_file_chunked(const char* auth_filename, const char* output_filename) {
    FILE* auth_file = fopen(auth_filename, "r");
    if (!auth_file) {
        printf("Error: Cannot open auth file %s: %s\n", auth_filename, strerror(errno));
        return 0;
    }
    
    FILE* output_file = fopen(output_filename, "w");
    if (!output_file) {
        printf("Error: Cannot create output file %s: %s\n", output_filename, strerror(errno));
        fclose(auth_file);
        return 0;
    }
    
    // Write CSV header
    fprintf(output_file, "features,label\n");
    
    // Allocate memory for one chunk
    auth_event_t* chunk = malloc(CHUNK_SIZE * sizeof(auth_event_t));
    if (!chunk) {
        printf("Error: Cannot allocate memory for chunk\n");
        fclose(auth_file);
        fclose(output_file);
        return 0;
    }
    
    char line[MAX_LINE_LENGTH];
    int total_processed = 0;
    int total_matches = 0;
    int chunk_count = 0;
    int current_chunk_size = 0;
    int skipped_lines = 0;
    
    printf("Processing authentication file in chunks of %d events...\n", CHUNK_SIZE);
    
    while (fgets(line, sizeof(line), auth_file)) {
        if (strlen(line) > 1) {  // Skip empty lines
            if (contains_question_mark(line)) {
                skipped_lines++;
                continue;
            }
            if (parse_auth_line(line, &chunk[current_chunk_size])) {
                current_chunk_size++;
                
                // If chunk is full, process it
                if (current_chunk_size >= CHUNK_SIZE) {
                    chunk_count++;
                    printf("\nProcessing chunk %d (%d events)...\n", chunk_count, current_chunk_size);
                    
                    if (!process_chunk(chunk, current_chunk_size, output_file, &total_matches)) {
                        printf("Error processing chunk %d\n", chunk_count);
                        free(chunk);
                        fclose(auth_file);
                        fclose(output_file);
                        return 0;
                    }
                    
                    total_processed += current_chunk_size;
                    printf("Chunk %d completed. Total processed: %d, Total matches: %d\n", 
                           chunk_count, total_processed, total_matches);
                    
                    current_chunk_size = 0;  // Reset for next chunk
                }
            }
        }
    }
    
    // Process the final partial chunk if it exists
    if (current_chunk_size > 0) {
        chunk_count++;
        printf("\nProcessing final chunk %d (%d events)...\n", chunk_count, current_chunk_size);
        
        if (!process_chunk(chunk, current_chunk_size, output_file, &total_matches)) {
            printf("Error processing final chunk\n");
            free(chunk);
            fclose(auth_file);
            fclose(output_file);
            return 0;
        }
        
        total_processed += current_chunk_size;
        printf("Final chunk completed. Total processed: %d, Total matches: %d\n", 
               total_processed, total_matches);
    }
    
    free(chunk);
    fclose(auth_file);
    fclose(output_file);
    
    printf("\nChunked processing completed!\n");
    printf("Total chunks processed: %d\n", chunk_count);
    printf("Total events processed: %d\n", total_processed);
    printf("Total matches found: %d\n", total_matches);
    if (skipped_lines > 0) {
        printf("Total lines skipped (containing '?'): %d\n", skipped_lines);
    }
    
    return total_processed;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <auth.txt> <redteam.txt> <output.csv>\n", argv[0]);
        return 1;
    }
    
    const char* auth_filename = argv[1];
    const char* redteam_filename = argv[2];
    const char* output_filename = argv[3];
    
    printf("Multi-threaded Chunked Data Preprocessor\n");
    printf("=======================================\n");
    printf("Auth file: %s\n", auth_filename);
    printf("Red team file: %s\n", redteam_filename);
    printf("Output file: %s\n", output_filename);
    printf("Threads: %d\n", NUM_THREADS);
    printf("Chunk size: %d events\n", CHUNK_SIZE);
    printf("Note: Lines containing '?' will be skipped\n\n");
    
    clock_t start_time = clock();
    
    // Load red team events first
    if (!load_redteam_events(redteam_filename)) {
        return 1;
    }
    
    // Process authentication events in chunks
    int processed = process_auth_file_chunked(auth_filename, output_filename);
    if (!processed) {
        return 1;
    }
    
    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    printf("\nProcessing completed successfully!\n");
    printf("Total events processed: %d\n", processed);
    printf("Red team events: %d\n", redteam_count);
    printf("Processing time: %.2f seconds\n", elapsed_time);
    printf("Average speed: %.0f events/second\n", processed / elapsed_time);
    printf("Output saved to: %s\n", output_filename);
    
    return 0;
}
