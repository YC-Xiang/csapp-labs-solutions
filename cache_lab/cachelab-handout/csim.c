#include "cachelab.h"
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #define DEBUG

#ifdef DEBUG
#define LOG_DBG(...) printf(__VA_ARGS__)
#else
#define LOG_DBG(...)
#endif

struct cache_para
{
	int sets;  // s
	int lines; // E
	int bits;  // b
	char *output_file;
	bool verbose_flag;
} cache;

struct cache_block
{
	unsigned long tag;
	int time;
	bool valid;
};

struct cache_simulator
{
	struct cache_block **blocks;
} cache_sim;

struct cache_result
{
	int hit;
	int miss;
	int eviction;
} result;

static void extract_parameters(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "hvs:E:b:t:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			printf("Usage: %s [-hv] -s <num> -E <num> -b <num> -t <file>\n", argv[0]);
			printf("Options:\n");
			printf("  -h\t\tPrint this help message.\n");
			printf("  -v\t\tOptional verbose flag.\n");
			printf("  -s <num>\tNumber of set index bits.\n");
			printf("  -E <num>\tNumber of lines per set.\n");
			printf("  -b <num>\tNumber of block offset bits.\n");
			printf("  -t <file>\tTrace file.\n");
			printf("\n");
			printf("Examples:\n");
			printf("linux> ./csim -s 4 -E 1 -b 4 -t traces/yi.trace\n");
			printf("linux> ./csim -v -s 8 -E 2 -b 4 -t traces/yi.trace\n");
			break;
		case 'v':
			cache.verbose_flag = true;
			break;
		case 's':
			cache.sets = atoi(optarg);
			break;
		case 'E':
			cache.lines = atoi(optarg);
			break;
		case 'b':
			cache.bits = atoi(optarg);
			break;
		case 't':
			cache.output_file = optarg;
			break;
		case '?':
			fprintf(stderr, "Unknown option: %c\n", optopt);
			break;
		default:
			break;
		}
	}
	LOG_DBG("cache: s=%d, E=%d, b=%d\n", cache.sets, cache.lines, cache.bits);
	LOG_DBG("trace file:%s\n", cache.output_file);
}

static void cache_rw(int s_idx, unsigned long tag, bool *hit, bool *miss,
		     bool *eviction)
{
	int idx = 0, max;

	// hit situation. valid must be 1 and tag==tag
	for (int i = 0; i < cache.lines; i++)
	{
		if ((cache_sim.blocks[s_idx][i].tag == tag) &&
		    (cache_sim.blocks[s_idx][i].valid == 1))
		{
			result.hit += 1;
			*hit = 1;
			cache_sim.blocks[s_idx][i].time = 0;

			if (cache.verbose_flag)
				printf("hit ");
			goto exit;
		}
	}

	// if there is no hit in cache. Then we should first find a free line to
	// store data. miss situation.
	for (int i = 0; i < cache.lines; i++)
	{
		if (cache_sim.blocks[s_idx][i].valid == 0)
		{
			cache_sim.blocks[s_idx][i].valid = 1;
			cache_sim.blocks[s_idx][i].tag = tag;
			result.miss += 1;
			*miss = 1;
			if (cache.verbose_flag)
				printf("miss ");
			goto exit;
		}
	}

	// If there is no free line, we should expire a line which valid must be 1 and
	// tag!=tag. eviction situation.
	result.eviction += 1;
	result.miss += 1;
	*eviction = 1;

	for (int i = 0; i < cache.lines; i++)
	{
		if (cache_sim.blocks[s_idx][i].time > max)
		{
			max = cache_sim.blocks[s_idx][i].time;
			idx = i;
		}
	}

	cache_sim.blocks[s_idx][idx].tag = tag;
	cache_sim.blocks[s_idx][idx].time = 0;

	if (cache.verbose_flag)
		printf("miss eviction ");

exit:
	for (int i = 0; i < cache.lines; i++)
	{
		if (cache_sim.blocks[s_idx][i].valid == 1)
			cache_sim.blocks[s_idx][i].time += 1;
	}
	return;
}

static int cache_process(char *line)
{
	char type;
	int size;
	unsigned long address, tag = 0;
	int s_idx;
	bool hit = 0, miss = 0, eviction = 0;

	sscanf(line, " %c %lx,%d\n", &type, &address, &size);

	s_idx = (address >> cache.bits) & ((1 << cache.sets) - 1);
	tag = address >> (cache.bits + cache.sets);

	if (cache.verbose_flag)
		printf("%c %lx,%d ", type, address, size);

	switch (type)
	{
	case 'L':
	case 'S':
		cache_rw(s_idx, tag, &hit, &miss, &eviction);
		break;
	case 'M':
		cache_rw(s_idx, tag, &hit, &miss, &eviction);
		cache_rw(s_idx, tag, &hit, &miss, &eviction);
		break;
	}

	if (cache.verbose_flag)
		printf("\n");

	return 0;
}

static int decode(char *file)
{
	FILE *fp;
	char line[50] = {0};
	int i;

	fp = fopen(file, "r");
	if (fp == NULL)
	{
		printf("open trace file failed\n");
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		if (line[0] != ' ') // skip 'I' which is loading instruction
			continue;

		i = 0;
		while (line[i] != '\n')
		{
			i++;
		}
		line[i] = '\0'; // remove the '\n' at the end of string

		cache_process(line);
	}

	return 0;
}

static void allocate_cache(void)
{
	int set_size = 2 << cache.sets; // S=2^s

	cache_sim.blocks =
	    (struct cache_block **)malloc(sizeof(struct cache_block *) * set_size);
	for (int i = 0; i < set_size; i++)
	{
		cache_sim.blocks[i] =
		    (struct cache_block *)malloc(sizeof(struct cache_block) * cache.lines);
		memset(cache_sim.blocks[i], 0x0, cache.lines * sizeof(struct cache_block));
	}
}

int main(int argc, char *argv[])
{

	int ret;

	// extract parameters from command lines
	extract_parameters(argc, argv);

	// malloc cache memory according to s,E,b
	allocate_cache();

	// decode trace files and process line by line
	ret = decode(cache.output_file);
	if (ret != 0)
		printf("decode error\n");

	printSummary(result.hit, result.miss, result.eviction);
	return 0;
}
