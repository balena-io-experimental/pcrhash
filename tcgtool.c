#include <argp.h>

#include "uefi.h"

enum action {
	ACTION_NONE,
	ACTION_MEASURE_EFIVAR,
	ACTION_HASH_EFIBIN,
};

struct tcgtool_arguments {
	enum action action;
	char *path;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct tcgtool_arguments *args = state->input;
	switch (key) {
		case 'e':
			args->action = ACTION_MEASURE_EFIVAR;
			args->path = arg;
			break;
		case 's':
			args->action = ACTION_HASH_EFIBIN;
			args->path = arg;
	}

	return 0;
}

static struct argp_option options[] = {
	{ 0, 0, 0, 0, "Measurements:" },
	{ "measure-efivar", 'e', "PATH", 0, "Measure an efivar, outputting the binary"
		" contents in an EFI_VARIABLE_DATA struct for hashing (default)" },
	{ "efibin-hash",   's', "EFI_BINARY", 0, "Generate SHA256 hash of an EFI binary"},
	{ 0 },
};

static char doc[] = "Measure and output data in accordance with the TCG PC"
	" Client Platform Firmware Profile specification";
static struct argp argp = { options, parse_opt, 0, doc, 0, 0, 0 };

int main(int argc, char **argv)
{
	struct tcgtool_arguments args = {
		.action = argc == 2 ? ACTION_MEASURE_EFIVAR : ACTION_NONE,
		.path = argv[1],
	};

	argp_parse(&argp, argc, argv, 0, 0, &args);

	switch (args.action) {
		case ACTION_MEASURE_EFIVAR:
			measure_efivar(args.path);
			break;
		case ACTION_HASH_EFIBIN:
			hash_efibin(args.path);
			break;
		default:
			printf("No action specified\n");
			break;
	}

	return 0;
}
