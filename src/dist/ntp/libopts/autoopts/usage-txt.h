/*	$NetBSD: usage-txt.h,v 1.1.1.1 2007/01/06 16:06:19 kardel Exp $	*/

/*   -*- buffer-read-only: t -*- vi: set ro:
 *  
 *  DO NOT EDIT THIS FILE   (usage-txt.h)
 *  
 *  It has been AutoGen-ed  Thursday October 12, 2006 at 05:44:43 PM PDT
 *  From the definitions    usage-txt.def
 *  and the template file   usage-txt.tpl
 *
 *  This file handles all the bookkeeping required for tracking all the little
 *  tiny strings used by the AutoOpts library.  There are 113
 *  of them.  This is not versioned because it is entirely internal to the
 *  library and accessed by client code only in a very well-controlled way:
 *  they may substitute translated strings using a procedure that steps through
 *  all the string pointers.
 *
 *  AutoOpts is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *  
 *  AutoOpts is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *  
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with AutoOpts.  If not, write to:
 *  	The Free Software Foundation, Inc.,
 *  	51 Franklin Street, Fifth Floor
 *  	Boston, MA  02110-1301, USA.
 */
#ifndef AUTOOPTS_USAGE_TXT_H_GUARD
#define AUTOOPTS_USAGE_TXT_H_GUARD

#undef  cch_t
#define cch_t char const

/*
 *  One structure to hold all the pointers to all the stringlets.
 */
typedef struct {
  int       field_ct;
  char*     utpz_GnuBoolArg;
  char*     utpz_GnuKeyArg;
  char*     utpz_GnuKeyLArg;
  char*     utpz_GnuNumArg;
  char*     utpz_GnuStrArg;
  cch_t*    apz_str[ 108 ];
} usage_text_t;

/*
 *  Declare the global structure with all the pointers to translated
 *  strings.  This is then used by the usage generation procedure.
 */
extern usage_text_t option_usage_text;

#if defined(AUTOOPTS_INTERNAL) /* DEFINE ALL THE STRINGS = = = = = */
/*
 *  Provide a mapping from a short name to fields in this structure.
 */
#define zAO_Bad               (option_usage_text.apz_str[  0])
#define zAO_Big               (option_usage_text.apz_str[  1])
#define zAO_Err               (option_usage_text.apz_str[  2])
#define zAO_Sml               (option_usage_text.apz_str[  3])
#define zAll                  (option_usage_text.apz_str[  4])
#define zAlt                  (option_usage_text.apz_str[  5])
#define zAmbigKey             (option_usage_text.apz_str[  6])
#define zAmbiguous            (option_usage_text.apz_str[  7])
#define zArgsMust             (option_usage_text.apz_str[  8])
#define zAtMost               (option_usage_text.apz_str[  9])
#define zAuto                 (option_usage_text.apz_str[ 10])
#define zBadPipe              (option_usage_text.apz_str[ 11])
#define zBadVerArg            (option_usage_text.apz_str[ 12])
#define zCantFmt              (option_usage_text.apz_str[ 13])
#define zCantSave             (option_usage_text.apz_str[ 14])
#define zDefaultOpt           (option_usage_text.apz_str[ 15])
#define zDis                  (option_usage_text.apz_str[ 16])
#define zEnab                 (option_usage_text.apz_str[ 17])
#define zEquiv                (option_usage_text.apz_str[ 18])
#define zErrOnly              (option_usage_text.apz_str[ 19])
#define zExamineFmt           (option_usage_text.apz_str[ 20])
#define zFiveSpaces           (option_usage_text.apz_str[ 21])
#define zFlagOkay             (option_usage_text.apz_str[ 22])
#define zFmtFmt               (option_usage_text.apz_str[ 23])
#define zForkFail             (option_usage_text.apz_str[ 24])
#define zFSErrOptLoad         (option_usage_text.apz_str[ 25])
#define zFSErrReadFile        (option_usage_text.apz_str[ 26])
#define zGenshell             (option_usage_text.apz_str[ 27])
#define zGnuBoolArg           (option_usage_text.utpz_GnuBoolArg)
#define zGnuBreak             (option_usage_text.apz_str[ 28])
#define zGnuKeyArg            (option_usage_text.utpz_GnuKeyArg)
#define zGnuKeyLArg           (option_usage_text.utpz_GnuKeyLArg)
#define zGnuNestArg           (option_usage_text.apz_str[ 29])
#define zGnuNumArg            (option_usage_text.utpz_GnuNumArg)
#define zGnuOptArg            (option_usage_text.apz_str[ 30])
#define zGnuOptFmt            (option_usage_text.apz_str[ 31])
#define zGnuStrArg            (option_usage_text.utpz_GnuStrArg)
#define zIllOptChr            (option_usage_text.apz_str[ 32])
#define zIllOptStr            (option_usage_text.apz_str[ 33])
#define zIllegal              (option_usage_text.apz_str[ 34])
#define zInvalOptDesc         (option_usage_text.apz_str[ 35])
#define zKeyWords             (option_usage_text.apz_str[ 36])
#define zLoadCooked           (option_usage_text.apz_str[ 37])
#define zLoadKeep             (option_usage_text.apz_str[ 38])
#define zLoadType             (option_usage_text.apz_str[ 39])
#define zLoadUncooked         (option_usage_text.apz_str[ 40])
#define zLtypeInteger         (option_usage_text.apz_str[ 41])
#define zLtypeNest            (option_usage_text.apz_str[ 42])
#define zLtypeString          (option_usage_text.apz_str[ 43])
#define zLtypeBool            (option_usage_text.apz_str[ 44])
#define zLtypeKeyword         (option_usage_text.apz_str[ 45])
#define zLtypeSetMembership   (option_usage_text.apz_str[ 46])
#define zMembers              (option_usage_text.apz_str[ 47])
#define zMisArg               (option_usage_text.apz_str[ 48])
#define zMultiEquiv           (option_usage_text.apz_str[ 49])
#define zMust                 (option_usage_text.apz_str[ 50])
#define zNeedOne              (option_usage_text.apz_str[ 51])
#define zNoArg                (option_usage_text.apz_str[ 52])
#define zNoArgs               (option_usage_text.apz_str[ 53])
#define zNoCreat              (option_usage_text.apz_str[ 54])
#define zNoFlags              (option_usage_text.apz_str[ 55])
#define zNoKey                (option_usage_text.apz_str[ 56])
#define zNoLim                (option_usage_text.apz_str[ 57])
#define zNoPreset             (option_usage_text.apz_str[ 58])
#define zNoRq_NoShrtTtl       (option_usage_text.apz_str[ 59])
#define zNoRq_ShrtTtl         (option_usage_text.apz_str[ 60])
#define zNoStat               (option_usage_text.apz_str[ 61])
#define zNoState              (option_usage_text.apz_str[ 62])
#define zNone                 (option_usage_text.apz_str[ 63])
#define zNotDef               (option_usage_text.apz_str[ 64])
#define zNotEnough            (option_usage_text.apz_str[ 65])
#define zNotFile              (option_usage_text.apz_str[ 66])
#define zNotNumber            (option_usage_text.apz_str[ 67])
#define zNrmOptFmt            (option_usage_text.apz_str[ 68])
#define zNumberOpt            (option_usage_text.apz_str[ 69])
#define zOneSpace             (option_usage_text.apz_str[ 70])
#define zOnlyOne              (option_usage_text.apz_str[ 71])
#define zOptsOnly             (option_usage_text.apz_str[ 72])
#define zPathFmt              (option_usage_text.apz_str[ 73])
#define zPlsSendBugs          (option_usage_text.apz_str[ 74])
#define zPreset               (option_usage_text.apz_str[ 75])
#define zPresetFile           (option_usage_text.apz_str[ 76])
#define zPresetIntro          (option_usage_text.apz_str[ 77])
#define zProg                 (option_usage_text.apz_str[ 78])
#define zProhib               (option_usage_text.apz_str[ 79])
#define zReorder              (option_usage_text.apz_str[ 80])
#define zReqFmt               (option_usage_text.apz_str[ 81])
#define zReqOptFmt            (option_usage_text.apz_str[ 82])
#define zReqThese             (option_usage_text.apz_str[ 83])
#define zReq_NoShrtTtl        (option_usage_text.apz_str[ 84])
#define zReq_ShrtTtl          (option_usage_text.apz_str[ 85])
#define zSepChars             (option_usage_text.apz_str[ 86])
#define zSetMembers           (option_usage_text.apz_str[ 87])
#define zSetMemberSettings    (option_usage_text.apz_str[ 88])
#define zShrtGnuOptFmt        (option_usage_text.apz_str[ 89])
#define zSixSpaces            (option_usage_text.apz_str[ 90])
#define zStdBoolArg           (option_usage_text.apz_str[ 91])
#define zStdBreak             (option_usage_text.apz_str[ 92])
#define zStdKeyArg            (option_usage_text.apz_str[ 93])
#define zStdKeyLArg           (option_usage_text.apz_str[ 94])
#define zStdNestArg           (option_usage_text.apz_str[ 95])
#define zStdNoArg             (option_usage_text.apz_str[ 96])
#define zStdNumArg            (option_usage_text.apz_str[ 97])
#define zStdOptArg            (option_usage_text.apz_str[ 98])
#define zStdReqArg            (option_usage_text.apz_str[ 99])
#define zStdStrArg            (option_usage_text.apz_str[100])
#define zTabHyp               (option_usage_text.apz_str[101])
#define zTabHypAnd            (option_usage_text.apz_str[102])
#define zTabout               (option_usage_text.apz_str[103])
#define zThreeSpaces          (option_usage_text.apz_str[104])
#define zTwoSpaces            (option_usage_text.apz_str[105])
#define zUpTo                 (option_usage_text.apz_str[106])
#define zValidKeys            (option_usage_text.apz_str[107])

  /*
   *  First, set up the strings.  Some of these are writable.  These are all in
   *  English.  This gets compiled into libopts and is distributed here so that
   *  xgettext (or equivalents) can extract these strings for translation.
   */

  static char    eng_zGnuBoolArg[] = "=T/F";
  static char    eng_zGnuKeyArg[] = "=KWd";
  static char    eng_zGnuKeyLArg[] = "=Mbr";
  static char    eng_zGnuNumArg[] = "=num";
  static char    eng_zGnuStrArg[] = "=str";
static char const usage_txt[3202] =
    "AutoOpts function called without option descriptor\n\0"
    "\tThis exceeds the compiled library version:  \0"
    "Automated Options Processing Error!\n"
    "\t%s called AutoOpts function with structure version %d:%d:%d.\n\0"
    "\tThis is less than the minimum library version:  \0"
    "all\0"
    "\t\t\t\t- an alternate for %s\n\0"
    "%s error:  the keyword `%s' is ambiguous\n\0"
    "ambiguous\0"
    "%s: Command line arguments required\n\0"
    "%4$d %1$s%s options allowed\n\0"
    "version and help options:\0"
    "Error %d (%s) from the pipe(2) syscall\n\0"
    "ERROR: version option argument '%c' invalid.  Use:\n"
    "\t'v' - version only\n"
    "\t'c' - version and copyright\n"
    "\t'n' - version and copyright notice\n\0"
    "ERROR:  %s option conflicts with the %s option\n\0"
    "%s(optionSaveState): error: cannot allocate %d bytes\n\0"
    "\t\t\t\t- default option for unnamed options\n\0"
    "\t\t\t\t- disabled as --%s\n\0"
    "\t\t\t\t- enabled by default\n\0"
    "-equivalence\0"
    "ERROR:  only \0"
    " - examining environment variables named %s_*\n\0"
    "     \0"
    "Options are specified by doubled hyphens and their name\n"
    "or by a single hyphen and the flag character.\n\0"
    "%%-%ds %%s\n\0"
    "fs error %d (%s) on fork - cannot obtain %s usage\n\0"
    "File error %d (%s) opening %s for loading options\n\0"
    "fs error %d (%s) reading file %s\n\0"
    "\n"
    "= = = = = = = =\n\n"
    "This incarnation of genshell will produce\n"
    "a shell script to parse the options for %s:\n\n\0"
    "\n"
    "%s\n\n\0"
    "=Cplx\0"
    "[=arg]\0"
    "--%2$s%1$s\0"
    "%s: illegal option -- %c\n\0"
    "%s: %s option -- %s\n\0"
    "illegal\0"
    "AutoOpts ERROR:  invalid option descriptor for %s\n\0"
    "words=\0"
    "cooked\0"
    "keep\0"
    "type=\0"
    "uncooked\0"
    "integer\0"
    "nested\0"
    "string\0"
    "bool\0"
    "keyword\0"
    "set\0"
    "\t\t\t\t- is a set membership option\n\0"
    "%s: option `%s' requires an argument\n\0"
    "Equivalenced option '%s' was equivalenced to both\n"
    "\t'%s' and '%s'\0"
    "\t\t\t\t- must appear between %d and %d times\n\0"
    "ERROR:  The %s option is required\n\0"
    "%s: option `%s' cannot have an argument\n\0"
    "%s: Command line arguments not allowed\n\0"
    "error %d (%s) creating %s\n\0"
    "Options are specified by single or double hyphens and their name.\n\0"
    "%s error:  `%s' does not match any keywords\n\0"
    "\t\t\t\t- may appear multiple times\n\0"
    "\t\t\t\t- may not be preset\n\0"
    "   Arg Option-Name    Description\n\0"
    "  Flg Arg Option-Name    Description\n\0"
    "error %d (%s) stat-ing %s\n\0"
    "%s(optionRestore): error: no saved option state\n\0"
    "none\0"
    "'%s' not defined\n\0"
    "ERROR:  The %s option must appear %d times\n\0"
    "error:  cannot load options from non-regular file %s\n\0"
    "%s error:  `%s' is not a recognizable number\n\0"
    " %3s %s\0"
    "The '-#<number>' option may omit the hash char\n\0"
    " \0"
    "one %s%s option allowed\n\0"
    "All arguments are named options.\n\0"
    " - reading file %s\0"
    "\n"
    "please send bug reports to:  %s\n\0"
    "\t\t\t\t- may NOT appear - preset only\n\0"
    "#  preset/initialization file\n"
    "#  %s#\n\0"
    "\n"
    "The following option preset mechanisms are supported:\n\0"
    "program\0"
    "prohibits these options:\n\0"
    "Operands and options may be intermixed.  They will be reordered.\n\0"
    "ERROR:  %s option requires the %s option\n\0"
    " %3s %-14s %s\0"
    "requires these options:\n\0"
    "   Arg Option-Name   Req?  Description\n\0"
    "  Flg Arg Option-Name   Req?  Description\n\0"
    "-_^\0"
    "members=\0"
    "or you may use a numeric representation.  Preceding these with a '!' will\n"
    "clear the bits, specifying 'none' will clear all bits, and 'all' will set them\n"
    "all.  Multiple entries may be passed as an option argument list.\n\0"
    "%s\0"
    "      \0"
    "T/F\0"
    "\n"
    "%s\n\n"
    "%s\0"
    "KWd\0"
    "Mbr\0"
    "Cpx\0"
    "no \0"
    "Num\0"
    "opt\0"
    "YES\0"
    "Str\0"
    "\t\t\t\t- \0"
    "\t\t\t\t-- and \0"
    "\t\t\t\t%s\n\0"
    "   \0"
    "  \0"
    "\t\t\t\t- may appear up to %d times\n\0"
    "The valid \"%s\" option keywords are:\n\0";


  /*
   *  Now, define (and initialize) the structure that contains
   *  the pointers to all these strings.
   *  Aren't you glad you don't maintain this by hand?
   */
  usage_text_t option_usage_text = {
    113,
    eng_zGnuBoolArg, eng_zGnuKeyArg,  eng_zGnuKeyLArg, eng_zGnuNumArg,
    eng_zGnuStrArg,
    {
      usage_txt +   0, usage_txt +  52, usage_txt +  98, usage_txt + 197,
      usage_txt + 247, usage_txt + 251, usage_txt + 278, usage_txt + 320,
      usage_txt + 330, usage_txt + 367, usage_txt + 396, usage_txt + 422,
      usage_txt + 462, usage_txt + 599, usage_txt + 647, usage_txt + 701,
      usage_txt + 743, usage_txt + 767, usage_txt + 793, usage_txt + 806,
      usage_txt + 820, usage_txt + 867, usage_txt + 873, usage_txt + 976,
      usage_txt + 988, usage_txt +1039, usage_txt +1090, usage_txt +1124,
      usage_txt +1230, usage_txt +1236, usage_txt +1242, usage_txt +1249,
      usage_txt +1260, usage_txt +1286, usage_txt +1307, usage_txt +1315,
      usage_txt +1366, usage_txt +1373, usage_txt +1380, usage_txt +1385,
      usage_txt +1391, usage_txt +1400, usage_txt +1408, usage_txt +1415,
      usage_txt +1422, usage_txt +1427, usage_txt +1435, usage_txt +1439,
      usage_txt +1473, usage_txt +1511, usage_txt +1576, usage_txt +1619,
      usage_txt +1654, usage_txt +1695, usage_txt +1735, usage_txt +1762,
      usage_txt +1829, usage_txt +1874, usage_txt +1907, usage_txt +1932,
      usage_txt +1967, usage_txt +2005, usage_txt +2032, usage_txt +2081,
      usage_txt +2086, usage_txt +2104, usage_txt +2148, usage_txt +2202,
      usage_txt +2248, usage_txt +2256, usage_txt +2304, usage_txt +2306,
      usage_txt +2331, usage_txt +2365, usage_txt +2384, usage_txt +2418,
      usage_txt +2454, usage_txt +2492, usage_txt +2548, usage_txt +2556,
      usage_txt +2582, usage_txt +2648, usage_txt +2690, usage_txt +2704,
      usage_txt +2729, usage_txt +2769, usage_txt +2812, usage_txt +2816,
      usage_txt +2825, usage_txt +3044, usage_txt +3047, usage_txt +3054,
      usage_txt +3058, usage_txt +3066, usage_txt +3070, usage_txt +3074,
      usage_txt +3078, usage_txt +3082, usage_txt +3086, usage_txt +3090,
      usage_txt +3094, usage_txt +3098, usage_txt +3105, usage_txt +3117,
      usage_txt +3125, usage_txt +3129, usage_txt +3132, usage_txt +3165
    }
  };

#endif /* DO_TRANSLATIONS */
#endif /* AUTOOPTS_USAGE_TXT_H_GUARD */