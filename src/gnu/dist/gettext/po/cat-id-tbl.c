/* Automatically generated by po2tbl.sed from gettext.pot.  */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include "libgettext.h"

const struct _msg_ent _msg_tbl[] = {
  {"", 1},
  {"Unknown system error", 2},
  {"%s: option `%s' is ambiguous\n", 3},
  {"%s: option `--%s' doesn't allow an argument\n", 4},
  {"%s: option `%c%s' doesn't allow an argument\n", 5},
  {"%s: option `%s' requires an argument\n", 6},
  {"%s: unrecognized option `--%s'\n", 7},
  {"%s: unrecognized option `%c%s'\n", 8},
  {"%s: illegal option -- %c\n", 9},
  {"%s: invalid option -- %c\n", 10},
  {"%s: option requires an argument -- %c\n", 11},
  {"%s: option `-W %s' is ambiguous\n", 12},
  {"%s: option `-W %s' doesn't allow an argument\n", 13},
  {"Memory exhausted", 14},
  {"\
Copyright (C) %s Free Software Foundation, Inc.\n\
This is free software; see the source for copying conditions.  There is NO\n\
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n", 15},
  {"Written by %s.\n", 16},
  {"missing arguments", 17},
  {"too many arguments", 18},
  {"Try `%s --help' for more information.\n", 19},
  {"\
Usage: %s [OPTION] [[[TEXTDOMAIN] MSGID] | [-s [MSGID]...]]\n\
  -d, --domain=TEXTDOMAIN   retrieve translated messages from TEXTDOMAIN\n\
  -e                        enable expansion of some escape sequences\n\
  -E                        (ignored for compatibility)\n\
  -h, --help                display this help and exit\n\
  -n                        suppress trailing newline\n\
  -V, --version             display version information and exit\n\
  [TEXTDOMAIN] MSGID        retrieve translated message corresponding\n\
                            to MSGID from TEXTDOMAIN\n", 20},
  {"\
\n\
If the TEXTDOMAIN parameter is not given, the domain is determined from the\n\
environment variable TEXTDOMAIN.  If the message catalog is not found in the\n\
regular directory, another location can be specified with the environment\n\
variable TEXTDOMAINDIR.\n\
When used with the -s option the program behaves like the `echo' command.\n\
But it does not simply copy its arguments to stdout.  Instead those messages\n\
found in the selected catalog are translated.\n\
Standard search directory: %s\n", 21},
  {"Report bugs to <bug-gnu-utils@gnu.org>.\n", 22},
  {"\
internationalized messages should not contain the `\\%c' escape sequence", 23},
  {"cannot create output file \"%s\"", 24},
  {"standard output", 25},
  {"error while writing \"%s\" file", 26},
  {"no input files given", 27},
  {"exactly 2 input files required", 28},
  {"\
Usage: %s [OPTION] def.po ref.po\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -D, --directory=DIRECTORY   add DIRECTORY to list for input files search\n\
  -h, --help                  display this help and exit\n\
  -V, --version               output version information and exit\n\
\n\
Compare two Uniforum style .po files to check that both contain the same\n\
set of msgid strings.  The def.po file is an existing PO file with the\n\
old translations.  The ref.po file is the last created PO file\n\
(generally by xgettext).  This is useful for checking that you have\n\
translated each and every message in your program.  Where an exact match\n\
cannot be found, fuzzy matching is used to produce better diagnostics.\n", 29},
  {"this message is used but not defined...", 30},
  {"...but this definition is similar", 31},
  {"this message is used but not defined in %s", 32},
  {"warning: this message is not used", 33},
  {"duplicate message definition", 34},
  {"...this is the location of the first definition", 35},
  {"this message has no definition in the \"%s\" domain", 36},
  {"while preparing output", 37},
  {"%s and %s are mutually exclusive", 38},
  {"at least two files must be specified", 39},
  {"impossible selection criteria specified (%d < n < %d)", 40},
  {"\
Usage: %s [OPTION] INPUTFILE ...\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -d, --default-domain=NAME      use NAME.po for output (instead of messages.po)\n\
  -D, --directory=DIRECTORY      add DIRECTORY to list for input files search\n\
  -e, --no-escape                do not use C escapes in output (default)\n\
  -E, --escape                   use C escapes in output, no extended chars\n\
  -f, --files-from=FILE          get list of input files from FILE\n\
      --force-po                 write PO file even if empty\n\
  -F, --sort-by-file             sort output by file location\n\
  -h, --help                     display this help and exit\n", 41},
  {"\
  -i, --indent                   write the .po file using indented style\n\
      --no-location              do not write '#: filename:line' lines\n\
  -n, --add-location             generate '#: filename:line' lines \
(default)\n\
      --omit-header              don't write header with `msgid \"\"' entry\n\
  -o, --output=FILE              write output to specified file\n\
  -p, --output-dir=DIR           output files will be placed in directory \
DIR\n\
  -s, --sort-output              generate sorted output and remove \
duplicates\n\
      --strict                   write out strict Uniforum conforming .po \
file\n\
  -T, --trigraphs                understand ANSI C trigraphs for input\n\
  -u, --unique                   shorthand for --less-than=2, requests\n\
                                 that only unique messages be printed\n", 42},
  {"\
  -V, --version                  output version information and exit\n\
  -w, --width=NUMBER             set output page width\n\
  -<, --less-than=NUMBER         print messages with less than this many\n\
                                 definitions, defaults to infinite if not\n\
                                 set\n\
  ->, --more-than=NUMBER         print messages with more than this many\n\
                                 definitions, defaults to 1 if not set\n\
\n\
Find messages which are common to two or more of the specified PO files.\n\
By using the --more-than option, greater commonality may be requested\n\
before messages are printed.  Conversely, the --less-than option may be\n\
used to specify less commonality before messages are printed (i.e.\n\
--less-than=2 will only print the unique messages).  Translations,\n\
comments and extract comments will be preserved, but only from the first\n\
PO file to define them.  File positions from all PO files will be\n\
preserved.\n", 43},
  {"error while opening \"%s\" for reading", 44},
  {"this file may not contain domain directives", 45},
  {"no input file given", 46},
  {"error while opening \"%s\" for writing", 47},
  {"%d translated messages", 48},
  {", %d fuzzy translations", 49},
  {", %d untranslated messages", 50},
  {"\
Usage: %s [OPTION] filename.po ...\n\
Generate binary message catalog from textual translation description.\n\
\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -a, --alignment=NUMBER      align strings to NUMBER bytes (default: %d)\n\
  -c, --check                 perform language dependent checks on strings\n\
  -D, --directory=DIRECTORY   add DIRECTORY to list for input files search\n\
  -f, --use-fuzzy             use fuzzy entries in output\n\
  -h, --help                  display this help and exit\n\
      --no-hash               binary file will not include the hash table\n\
  -o, --output-file=FILE      specify output file name as FILE\n\
      --statistics            print statistics about translations\n\
      --strict                enable strict Uniforum mode\n\
  -v, --verbose               list input file anomalies\n\
  -V, --version               output version information and exit\n\
\n\
Giving the -v option more than once increases the verbosity level.\n\
\n\
If input file is -, standard input is read.  If output file is -,\n\
output is written to standard output.\n", 51},
  {"while creating hash table", 52},
  {"%s: warning: no header entry found", 53},
  {"domain name \"%s\" not suitable as file name", 54},
  {"domain name \"%s\" not suitable as file name: will use prefix", 55},
  {"`domain %s' directive ignored", 56},
  {"empty `msgstr' entry ignored", 57},
  {"fuzzy `msgstr' entry ignored", 58},
  {"headerfield `%s' missing in header", 59},
  {"header field `%s' should start at beginning of line", 60},
  {"some header fields still have the initial default value", 61},
  {"field `%s' still has initial default value", 62},
  {"%s: warning: source file contains fuzzy translation", 63},
  {"`msgid' and `msgstr' entries do not both begin with '\\n'", 64},
  {"`msgid' and `msgstr' entries do not both end with '\\n'", 65},
  {"number of format specifications in `msgid' and `msgstr' does not match", 66},
  {"format specifications for argument %u are not the same", 67},
  {"\
Usage: %s [OPTION] def.po ref.po\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -D, --directory=DIRECTORY   add DIRECTORY to list for input files search\n\
  -e, --no-escape             do not use C escapes in output (default)\n\
  -E, --escape                use C escapes in output, no extended chars\n\
      --force-po              write PO file even if empty\n\
  -h, --help                  display this help and exit\n\
  -i, --indent                indented output style\n\
  -o, --output-file=FILE      result will be written to FILE\n\
      --no-location           suppress '#: filename:line' lines\n\
      --add-location          preserve '#: filename:line' lines (default)\n\
      --strict                strict Uniforum output style\n\
  -v, --verbose               increase verbosity level\n\
  -V, --version               output version information and exit\n\
  -w, --width=NUMBER          set output page width\n", 68},
  {"\
\n\
Merges two Uniforum style .po files together.  The def.po file is an\n\
existing PO file with the old translations which will be taken over to\n\
the newly created file as long as they still match; comments will be\n\
preserved, but extract comments and file positions will be discarded.\n\
The ref.po file is the last created PO file (generally by xgettext), any\n\
translations or comments in the file will be discarded, however dot\n\
comments and file positions will be preserved.  Where an exact match\n\
cannot be found, fuzzy matching is used to produce better results.  The\n\
results are written to stdout unless an output file is specified.\n", 69},
  {"\
%sRead %d old + %d reference, merged %d, fuzzied %d, missing %d, obsolete \
%d.\n", 70},
  {" done.\n", 71},
  {"\
Usage: %s [OPTION] [FILE]...\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -e, --no-escape          do not use C escapes in output (default)\n\
  -E, --escape             use C escapes in output, no extended chars\n\
      --force-po           write PO file even if empty\n\
  -h, --help               display this help and exit\n\
  -i, --indent             write indented output style\n\
  -o, --output-file=FILE   write output into FILE instead of standard output\n\
      --strict             write strict uniforum style\n\
  -V, --version            output version information and exit\n\
  -w, --width=NUMBER       set output page width\n", 72},
  {"\
\n\
Convert binary .mo files to Uniforum style .po files.\n\
Both little-endian and big-endian .mo files are handled.\n\
If no input file is given or it is -, standard input is read.\n\
By default the output is written to standard output.\n", 73},
  {"error while reading \"%s\"", 74},
  {"file \"%s\" truncated", 75},
  {"seek \"%s\" offset %ld failed", 76},
  {"file \"%s\" is not in GNU .mo format", 77},
  {"missing `msgstr' section", 78},
  {"found %d fatal errors", 79},
  {"too many errors, aborting", 80},
  {"keyword \"%s\" unknown", 81},
  {"illegal control sequence", 82},
  {"end-of-line within string", 83},
  {"end-of-file within string", 84},
  {"standard input", 85},
  {"%s:%d: warning: unterminated character constant", 86},
  {"%s:%d: warning: unterminated string literal", 87},
  {"--join-existing cannot be used when output is written to stdout", 88},
  {"warning: file `%s' extension `%s' is unknown; will try C", 89},
  {"\
Usage: %s [OPTION] INPUTFILE ...\n\
Extract translatable string from given input files.\n\
\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -a, --extract-all              extract all strings\n\
  -c, --add-comments[=TAG]       place comment block with TAG (or those\n\
                                 preceding keyword lines) in output file\n\
  -C, --c++                      shorthand for --language=C++\n\
      --debug                    more detailed formatstring recognision result\n\
  -d, --default-domain=NAME      use NAME.po for output (instead of messages.po)\n\
  -D, --directory=DIRECTORY      add DIRECTORY to list for input files search\n\
  -e, --no-escape                do not use C escapes in output (default)\n\
  -E, --escape                   use C escapes in output, no extended chars\n\
  -f, --files-from=FILE          get list of input files from FILE\n\
      --force-po                 write PO file even if empty\n\
      --foreign-user             omit FSF copyright in output for foreign user\n\
  -F, --sort-by-file             sort output by file location\n", 90},
  {"\
  -h, --help                     display this help and exit\n\
  -i, --indent                   write the .po file using indented style\n\
  -j, --join-existing            join messages with existing file\n\
  -k, --keyword[=WORD]           additonal keyword to be looked for (without\n\
                                 WORD means not to use default keywords)\n\
  -l, --string-limit=NUMBER      set string length limit to NUMBER instead %u\n\
  -L, --language=NAME            recognise the specified language (C, C++, PO),\n\
                                 otherwise is guessed from file extension\n\
  -m, --msgstr-prefix[=STRING]   use STRING or \"\" as prefix for msgstr entries\n\
  -M, --msgstr-suffix[=STRING]   use STRING or \"\" as suffix for msgstr entries\n\
      --no-location              do not write '#: filename:line' lines\n", 91},
  {"\
  -n, --add-location             generate '#: filename:line' lines (default)\n\
      --omit-header              don't write header with `msgid \"\"' entry\n\
  -o, --output=FILE              write output to specified file\n\
  -p, --output-dir=DIR           output files will be placed in directory DIR\n\
  -s, --sort-output              generate sorted output and remove duplicates\n\
      --strict                   write out strict Uniforum conforming .po file\n\
  -T, --trigraphs                understand ANSI C trigraphs for input\n\
  -V, --version                  output version information and exit\n\
  -w, --width=NUMBER             set output page width\n\
  -x, --exclude-file=FILE        entries from FILE are not extracted\n\
\n\
If INPUTFILE is -, standard input is read.\n", 92},
  {"language `%s' unknown", 93},
};

int _msg_tbl_length = 93;