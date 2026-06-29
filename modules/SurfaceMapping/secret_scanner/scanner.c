#include <pthread.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LINE 4096
#define MAX_MATCHES 1000
#define MAX_WORKERS 16
#define MAX_PATTERNS 20

typedef struct {
  char *pattern;
  char *type;
  char *severity;
  regex_t regex;
} SecretPattern;

typedef struct {
  char *url;
  char *filename;
  SecretPattern *patterns;
  int pattern_count;
} WorkerArgs;

typedef struct {
  char type[64];
  char secret[256];
  char severity[16];
  int line;
  char context[512];
} Finding;

// Patterns compilados em tempo de compilação
SecretPattern patterns[] = {
    {"AKIA[0-9A-Z]{16}", "AWS Access Key", "critical"},
    {"(?i)api[_-]?key[\"\\s:=]+['\"]?([a-zA-Z0-9_-]{20,})", "API Key",
     "critical"},
    {"AIza[0-9A-Za-z\\-_]{35}", "Google API Key", "high"},
    {"eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+",
     "JWT Token", "high"},
    {"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----", "Private Key", "critical"},
    {"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token", "high"},
    {"xox[baprs]-[A-Za-z0-9\\-_]+", "Slack Token", "high"},
    {"sk_(test|live)_[A-Za-z0-9]{24,}", "Stripe Secret Key", "critical"},
    {"(?i)mongodb://[^\\s\"']+", "MongoDB URL", "critical"},
    {"(?i)redis://[^\\s\"']+", "Redis URL", "high"},
    {NULL, NULL, NULL}};

int compile_patterns(SecretPattern *patterns) {
  for (int i = 0; patterns[i].pattern != NULL; i++) {
    int ret = regcomp(&patterns[i].regex, patterns[i].pattern,
                      REG_EXTENDED | REG_ICASE | REG_NEWLINE);
    if (ret != 0) {
      fprintf(stderr, "Failed to compile pattern: %s\n", patterns[i].pattern);
      return -1;
    }
  }
  return 0;
}

void scan_file(const char *filename, const char *url, SecretPattern *patterns,
               int pattern_count, FILE *output) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    return;
  }

  char line[MAX_LINE];
  int line_num = 0;
  Finding findings[MAX_MATCHES];
  int finding_count = 0;

  while (fgets(line, sizeof(line), fp) != NULL && finding_count < MAX_MATCHES) {
    line_num++;

    // Remove newline
    line[strcspn(line, "\r\n")] = 0;

    for (int i = 0; i < pattern_count; i++) {
      regmatch_t matches[3];
      if (regexec(&patterns[i].regex, line, 3, matches, 0) == 0) {
        Finding *f = &findings[finding_count++];
        strncpy(f->type, patterns[i].type, sizeof(f->type) - 1);
        strncpy(f->severity, patterns[i].severity, sizeof(f->severity) - 1);
        f->line = line_num;

        // Extrai o segredo encontrado
        int start = matches[1].rm_so >= 0 ? matches[1].rm_so : matches[0].rm_so;
        int end = matches[1].rm_eo >= 0 ? matches[1].rm_eo : matches[0].rm_eo;
        int len = end - start;
        if (len < sizeof(f->secret)) {
          strncpy(f->secret, line + start, len);
          f->secret[len] = '\0';

          // Mascara parte do segredo
          if (len > 8) {
            for (int j = 4; j < len - 4; j++) {
              f->secret[j] = '*';
            }
          }
        }

        // Contexto (trunca se necessário)
        strncpy(f->context, line, sizeof(f->context) - 1);
        if (strlen(line) > sizeof(f->context) - 1) {
          f->context[sizeof(f->context) - 4] = '.';
          f->context[sizeof(f->context) - 3] = '.';
          f->context[sizeof(f->context) - 2] = '.';
          f->context[sizeof(f->context) - 1] = '\0';
        }
      }
    }
  }

  fclose(fp);

  // Output findings as JSON
  for (int i = 0; i < finding_count; i++) {
    fprintf(output,
            "{\"url\":\"%s\",\"type\":\"%s\",\"secret\":\"%s\","
            "\"severity\":\"%s\",\"line\":%d,\"context\":\"%s\"}\n",
            url, findings[i].type, findings[i].secret, findings[i].severity,
            findings[i].line, findings[i].context);
  }
}

void *worker(void *arg) {
  WorkerArgs *args = (WorkerArgs *)arg;
  scan_file(args->filename, args->url, args->patterns, args->pattern_count,
            stdout);
  free(args->filename);
  free(args->url);
  free(args);
  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <filelist.txt> <output.json>\n", argv[0]);
    fprintf(stderr, "filelist.txt format: URL|FILENAME per line\n");
    return 1;
  }

  // Compila patterns
  int pattern_count = 0;
  while (patterns[pattern_count].pattern != NULL)
    pattern_count++;

  if (compile_patterns(patterns) != 0) {
    return 1;
  }

  // Lê lista de arquivos
  FILE *list = fopen(argv[1], "r");
  if (!list) {
    perror("fopen");
    return 1;
  }

  char line[MAX_LINE * 2];
  pthread_t threads[MAX_WORKERS];
  int thread_count = 0;

  printf("[\n"); // Inicia JSON array

  while (fgets(line, sizeof(line), list) != NULL) {
    line[strcspn(line, "\r\n")] = 0;

    char *url = strtok(line, "|");
    char *filename = strtok(NULL, "|");

    if (!url || !filename)
      continue;

    WorkerArgs *args = malloc(sizeof(WorkerArgs));
    args->url = strdup(url);
    args->filename = strdup(filename);
    args->patterns = patterns;
    args->pattern_count = pattern_count;

    if (thread_count < MAX_WORKERS) {
      pthread_create(&threads[thread_count++], NULL, worker, args);
    } else {
      // Wait for one thread to finish
      pthread_join(threads[--thread_count], NULL);
      pthread_create(&threads[thread_count++], NULL, worker, args);
    }
  }

  // Join remaining threads
  for (int i = 0; i < thread_count; i++) {
    pthread_join(threads[i], NULL);
  }

  printf("]\n"); // Fecha JSON array
  fclose(list);

  // Cleanup
  for (int i = 0; i < pattern_count; i++) {
    regfree(&patterns[i].regex);
  }

  return 0;
}