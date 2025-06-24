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
#define MAX_REDTEAM_EVENTS 1000000
#define MAX_COMPUTERS_LIMIT 10  // Limit to 10 unique computers (as per original code, not 300 from comment)

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

// Structure to track unique computers
typedef struct {
    char computers[MAX_COMPUTERS_LIMIT][256];
    int count;
    pthread_mutex_t mutex;
} computer_set_t;

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
    computer_set_t *computer_set;
} thread_data_t;

// Global variables
static redteam_event_t redteam_events[MAX_REDTEAM_EVENTS];
static int redteam_count = 0;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t match_mutex = PTHREAD_MUTEX_INITIALIZER;
static computer_set_t global_computer_set = {.count = 0, .mutex = PTHREAD_MUTEX_INITIALIZER};

// Time window for matching red team events (in seconds)
// Auth event time must be >= rt_event.time AND <= rt_event.time + MATCH_TIME_WINDOW_SECONDS
#define MATCH_TIME_WINDOW_SECONDS 5 

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

// Function to check if computer is in the allowed set
int is_computer_allowed(const char* computer, computer_set_t* comp_set) {
    pthread_mutex_lock(&comp_set->mutex);
    
    for (int i = 0; i < comp_set->count; i++) {
        if (strcmp(comp_set->computers[i], computer) == 0) {
            pthread_mutex_unlock(&comp_set->mutex);
            return 1;
        }
    }
    
    if (comp_set->count < MAX_COMPUTERS_LIMIT) {
        strncpy(comp_set->computers[comp_set->count], computer, 255);
        comp_set->computers[comp_set->count][255] = '\0';
        comp_set->count++;
        pthread_mutex_unlock(&comp_set->mutex);
        return 1;
    }
    
    pthread_mutex_unlock(&comp_set->mutex);
    return 0;
}

// Function to add red team computers to the allowed set
void add_redteam_computers_to_set(computer_set_t* comp_set) {
    pthread_mutex_lock(&comp_set->mutex);
    
    for (int i = 0; i < redteam_count && comp_set->count < MAX_COMPUTERS_LIMIT; i++) {
        int found_source = 0;
        for (int j = 0; j < comp_set->count; j++) {
            if (strcmp(comp_set->computers[j], redteam_events[i].source_computer) == 0) {
                found_source = 1;
                break;
            }
        }
        if (!found_source && comp_set->count < MAX_COMPUTERS_LIMIT) {
            strncpy(comp_set->computers[comp_set->count], redteam_events[i].source_computer, 255);
            comp_set->computers[comp_set->count][255] = '\0';
            comp_set->count++;
        }
        
        // Ensure not to double-add if source and dest computers are the same and limit is tight
        if (comp_set->count >= MAX_COMPUTERS_LIMIT) break;

        int found_dest = 0;
        for (int j = 0; j < comp_set->count; j++) {
            if (strcmp(comp_set->computers[j], redteam_events[i].dest_computer) == 0) {
                found_dest = 1;
                break;
            }
        }
        if (!found_dest && comp_set->count < MAX_COMPUTERS_LIMIT) {
            strncpy(comp_set->computers[comp_set->count], redteam_events[i].dest_computer, 255);
            comp_set->computers[comp_set->count][255] = '\0';
            comp_set->count++;
        }
    }
    
    pthread_mutex_unlock(&comp_set->mutex);
    printf("Added red team computers to allowed set. Current count: %d\n", comp_set->count);
}

// Function to check if an auth event should be processed based on computer sampling
int should_process_auth_event(auth_event_t* auth, computer_set_t* comp_set) {
    return (is_computer_allowed(auth->source_computer, comp_set) || 
            is_computer_allowed(auth->dest_computer, comp_set));
}

// Function to parse authentication line
int parse_auth_line(char* line, auth_event_t* event) {
    if (contains_question_mark(line)) {
        return 0;
    }
    
    char* token;
    char* line_copy = strdup(line);
    if (!line_copy) { perror("strdup failed in parse_auth_line"); return 0; }
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
    if (contains_question_mark(line)) {
        return 0;
    }
    
    char* token;
    char* line_copy = strdup(line);
    if (!line_copy) { perror("strdup failed in parse_redteam_line"); return 0; }
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

// Function to check if an auth event matches a red team event (STRICTER VERSION)
// An auth_event is considered a "red team event" if it directly corresponds
// to a specific event listed in the redteam_events list, within a defined time window.
int is_redteam_event(auth_event_t* auth, redteam_event_t* redteam_events_list, int redteam_count) {
    for (int i = 0; i < redteam_count; i++) {
        redteam_event_t* rt_event = &redteam_events_list[i];

        // Criterion 1: Time match
        // Auth event time must be >= red team event time AND <= red team event time + window.
        if (! (auth->time >= rt_event->time && auth->time <= (rt_event->time + MATCH_TIME_WINDOW_SECONDS)) ) {
            continue; // Time out of window for this red team event
        }

        // Criterion 2: User match
        // The redteam_event.user is the actor. In an auth_event, this typically corresponds to the source_user.
        if (strcmp(auth->source_user, rt_event->user) != 0) {
            continue; // User doesn't match
        }

        // Criterion 3: Source computer match
        if (strcmp(auth->source_computer, rt_event->source_computer) != 0) {
            continue; // Source computer doesn't match
        }

        // Criterion 4: Destination computer match
        if (strcmp(auth->dest_computer, rt_event->dest_computer) != 0) {
            continue; // Destination computer doesn't match
        }

        // If all criteria are met, this auth_event is a direct match for rt_event[i].
        printf("STRICT MATCH FOUND: AuthEvent(T:%d,U:%s,SC:%s,DC:%s) matches RedTeamEvent(Index:%d,T:%d,U:%s,SC:%s,DC:%s)\n",
               auth->time, auth->source_user, auth->source_computer, auth->dest_computer,
               i, rt_event->time, rt_event->user, rt_event->source_computer, rt_event->dest_computer);
        return 1; // Mark as red team
    }
    return 0; // No specific red team event fully matched this auth event
}


// Thread worker function
void* process_auth_events(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    char output_line[2048]; // Increased buffer size for safety
    int processed_by_thread = 0;
    int matches_found_by_thread = 0;
    // int skipped_sampling_by_thread = 0; // If you need to track this per thread
    
    for (int i = data->start_idx; i < data->end_idx; i++) {
        auth_event_t* event = &data->auth_events[i];
        
        if (!should_process_auth_event(event, data->computer_set)) {
            // skipped_sampling_by_thread++;
            continue;
        }
        
        int is_redteam = is_redteam_event(event, data->redteam_events, data->redteam_count);
        if (is_redteam) {
            matches_found_by_thread++;
        }
        
        snprintf(output_line, sizeof(output_line), 
                "%d,%s,%s,%s,%s,%s,%s,%s,%s,%d\n",
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
        
        pthread_mutex_lock(data->file_mutex);
        fprintf(data->output_file, "%s", output_line);
        pthread_mutex_unlock(data->file_mutex);
        
        processed_by_thread++;
    }
    
    pthread_mutex_lock(data->match_mutex);
    *(data->total_matches) += matches_found_by_thread;
    pthread_mutex_unlock(data->match_mutex);
    
    // Optional: Log per-thread stats, e.g. using data->thread_id
    // printf("Thread %d: Processed %d events, found %d matches, skipped %d due to sampling.\n", 
    //        data->thread_id, processed_by_thread, matches_found_by_thread, skipped_sampling_by_thread);

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
        if (strlen(line) > 1) { 
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
        printf("Skipped %d lines containing '?' characters from red team file\n", skipped_lines);
    }
    
    add_redteam_computers_to_set(&global_computer_set);
    
    return redteam_count;
}

// Function to process a chunk of authentication events
int process_chunk(auth_event_t* chunk, int chunk_current_size, FILE* output_file, int* total_matches) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    if (chunk_current_size == 0) return 1; // Nothing to process

    int events_per_thread = chunk_current_size / NUM_THREADS;
    int remaining_events = chunk_current_size % NUM_THREADS;
    int current_event_idx = 0;

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].auth_events = chunk;
        thread_data[i].start_idx = current_event_idx;
        int events_for_this_thread = events_per_thread + (i < remaining_events ? 1 : 0);
        thread_data[i].end_idx = current_event_idx + events_for_this_thread;
        current_event_idx += events_for_this_thread;

        if (events_for_this_thread == 0 && thread_data[i].start_idx == chunk_current_size) {
            // No events for this thread if chunk_current_size < NUM_THREADS and all events assigned
            thread_data[i].start_idx = 0; // Avoid invalid range for loop in thread
            thread_data[i].end_idx = 0;   // No work for this thread
        }
        
        thread_data[i].redteam_events = redteam_events;
        thread_data[i].redteam_count = redteam_count;
        thread_data[i].output_file = output_file;
        thread_data[i].file_mutex = &file_mutex;
        thread_data[i].thread_id = i;
        thread_data[i].total_matches = total_matches;
        thread_data[i].match_mutex = &match_mutex;
        thread_data[i].computer_set = &global_computer_set;
        
        if (events_for_this_thread > 0) { // Only create thread if there's work
            if (pthread_create(&threads[i], NULL, process_auth_events, &thread_data[i]) != 0) {
                printf("Error creating thread %d: %s\n", i, strerror(errno));
                // Handle error: potentially join already created threads and then return 0
                for (int k=0; k<i; ++k) pthread_join(threads[k], NULL);
                return 0;
            }
        }
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        // Only join threads that were actually created (had work)
        if (thread_data[i].end_idx > thread_data[i].start_idx) {
             pthread_join(threads[i], NULL);
        }
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
    
    fprintf(output_file, "time,source user@domain,destination user@domain,source computer,destination computer,authentication type,logon type,authentication orientation,success/failure,label\n");
    
    auth_event_t* chunk = malloc(CHUNK_SIZE * sizeof(auth_event_t));
    if (!chunk) {
        printf("Error: Cannot allocate memory for chunk: %s\n", strerror(errno));
        fclose(auth_file);
        fclose(output_file);
        return 0;
    }
    
    char line[MAX_LINE_LENGTH];
    int total_processed_events = 0;
    int total_matches = 0;
    int chunk_num = 0;
    int current_chunk_idx = 0;
    int skipped_auth_lines = 0;
    
    printf("Processing authentication file in chunks of %d events...\n", CHUNK_SIZE);
    printf("Computer limit: %d unique computers\n", MAX_COMPUTERS_LIMIT);
    printf("Red team event match window: %d seconds\n", MATCH_TIME_WINDOW_SECONDS);
    
    while (fgets(line, sizeof(line), auth_file)) {
        if (strlen(line) > 1) { 
            if (contains_question_mark(line)) {
                skipped_auth_lines++;
                continue;
            }
            if (parse_auth_line(line, &chunk[current_chunk_idx])) {
                current_chunk_idx++;
                
                if (current_chunk_idx >= CHUNK_SIZE) {
                    chunk_num++;
                    printf("\nProcessing chunk %d (%d events)...\n", chunk_num, current_chunk_idx);
                    
                    if (!process_chunk(chunk, current_chunk_idx, output_file, &total_matches)) {
                        printf("Error processing chunk %d\n", chunk_num);
                        free(chunk);
                        fclose(auth_file);
                        fclose(output_file);
                        return 0;
                    }
                    
                    total_processed_events += current_chunk_idx;
                    printf("Chunk %d completed. Total events processed so far: %d, Total matches: %d\n", 
                           chunk_num, total_processed_events, total_matches);
                    printf("Unique computers tracked: %d\n", global_computer_set.count);
                    
                    current_chunk_idx = 0; 
                }
            } else {
                // Consider logging lines that fail parsing if not just due to '?'
                // printf("Warning: Failed to parse auth line: %s", line); 
            }
        }
    }
    
    if (current_chunk_idx > 0) {
        chunk_num++;
        printf("\nProcessing final chunk %d (%d events)...\n", chunk_num, current_chunk_idx);
        
        if (!process_chunk(chunk, current_chunk_idx, output_file, &total_matches)) {
            printf("Error processing final chunk\n");
            free(chunk);
            fclose(auth_file);
            fclose(output_file);
            return 0;
        }
        
        total_processed_events += current_chunk_idx;
        printf("Final chunk completed. Total events processed: %d, Total matches: %d\n", 
               total_processed_events, total_matches);
    }
    
    free(chunk);
    fclose(auth_file);
    fclose(output_file);
    
    printf("\nChunked processing completed!\n");
    printf("Total chunks processed: %d\n", chunk_num);
    printf("Total auth events processed and written: %d\n", total_processed_events);
    printf("Total matches found (label=1): %d\n", total_matches);
    printf("Unique computers tracked: %d (limit: %d)\n", global_computer_set.count, MAX_COMPUTERS_LIMIT);
    if (skipped_auth_lines > 0) {
        printf("Total auth lines skipped (containing '?'): %d\n", skipped_auth_lines);
    }
    
    return total_processed_events;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <auth.txt> <redteam.txt> <output.csv>\n", argv[0]);
        return 1;
    }
    
    const char* auth_filename = argv[1];
    const char* redteam_filename = argv[2];
    const char* output_filename = argv[3];
    
    printf("Multi-threaded Chunked Data Preprocessor with Computer Sampling\n");
    printf("==============================================================\n");
    printf("Auth file: %s\n", auth_filename);
    printf("Red team file: %s\n", redteam_filename);
    printf("Output file: %s\n", output_filename);
    printf("Threads: %d\n", NUM_THREADS);
    printf("Chunk size: %d events\n", CHUNK_SIZE);
    printf("Computer limit: %d unique computers\n", MAX_COMPUTERS_LIMIT);
    printf("Red team event match window: +/- %d seconds from auth event time.\n", MATCH_TIME_WINDOW_SECONDS);
    printf("Note: Lines containing '?' will be skipped from both auth and redteam files.\n");
    printf("Note: Red team computers are prioritized for tracking.\n\n");
    
    clock_t start_time_wc = clock(); // Wall-clock time for process
    time_t start_time_rt; time(&start_time_rt); // Real time
    
    if (!load_redteam_events(redteam_filename)) {
        // Error message already printed in load_redteam_events
        return 1;
    }
    if (redteam_count == 0) {
        printf("Warning: No red team events loaded. All output labels will be 0.\n");
    }
    
    int processed_count = process_auth_file_chunked(auth_filename, output_filename);
    // process_auth_file_chunked will return 0 on critical error, non-zero for count otherwise.
    // If it's 0 because the file was empty, that's fine. If it's 0 due to error, message printed.

    clock_t end_time_wc = clock();
    time_t end_time_rt; time(&end_time_rt);
    double elapsed_wc_time = ((double)(end_time_wc - start_time_wc)) / CLOCKS_PER_SEC;
    double elapsed_rt_time = difftime(end_time_rt, start_time_rt);
    
    printf("\nOverall processing summary:\n");
    printf("Total authentication events processed and written: %d\n", processed_count);
    printf("Red team definition events loaded: %d\n", redteam_count);
    printf("Unique computers tracked: %d (Limit: %d)\n", global_computer_set.count, MAX_COMPUTERS_LIMIT);
    printf("Wall-clock processing time: %.2f seconds\n", elapsed_wc_time);
    printf("Real time elapsed: %.2f seconds\n", elapsed_rt_time);
    if (elapsed_rt_time > 0.01) { // Avoid division by zero or tiny numbers
      printf("Approximate average speed: %.0f events/second (based on real time)\n", processed_count / elapsed_rt_time);
    }
    printf("Output saved to: %s\n", output_filename);
    
    // Clean up mutexes (optional for globals at program exit, but good practice)
    pthread_mutex_destroy(&file_mutex);
    pthread_mutex_destroy(&match_mutex);
    pthread_mutex_destroy(&global_computer_set.mutex);

    return 0;
}