/*	$NetBSD: version.c,v 1.1.1.1 2007/01/06 16:08:10 kardel Exp $	*/


/*  Id: version.c,v 4.9 2006/09/24 02:11:16 bkorb Exp
 * Time-stamp:      "2006-09-22 18:15:00 bkorb"
 *
 *  This module implements the default usage procedure for
 *  Automated Options.  It may be overridden, of course.
 */

static char const zAOV[] =
    "Automated Options version %s, copyright (c) 1999-2006 Bruce Korb\n";

/*  Automated Options is free software.
 *  You may redistribute it and/or modify it under the terms of the
 *  GNU General Public License, as published by the Free Software
 *  Foundation; either version 2, or (at your option) any later version.
 *
 *  Automated Options is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Automated Options.  See the file "COPYING".  If not,
 *  write to:  The Free Software Foundation, Inc.,
 *             51 Franklin Street, Fifth Floor,
 *             Boston, MA  02110-1301, USA.
 *
 * As a special exception, Bruce Korb gives permission for additional
 * uses of the text contained in his release of AutoOpts.
 *
 * The exception is that, if you link the AutoOpts library with other
 * files to produce an executable, this does not by itself cause the
 * resulting executable to be covered by the GNU General Public License.
 * Your use of that executable is in no way restricted on account of
 * linking the AutoOpts library code into it.
 *
 * This exception does not however invalidate any other reasons why
 * the executable file might be covered by the GNU General Public License.
 *
 * This exception applies only to the code released by Bruce Korb under
 * the name AutoOpts.  If you copy code from other sources under the
 * General Public License into a copy of AutoOpts, as the General Public
 * License permits, the exception does not apply to the code that you add
 * in this way.  To avoid misleading anyone as to the status of such
 * modified files, you must delete this exception notice from them.
 *
 * If you write modifications of your own for AutoOpts, it is your choice
 * whether to permit this exception to apply to your modifications.
 * If you do not wish that, delete this exception notice.
 */

/* = = = START-STATIC-FORWARD = = = */
/* static forward declarations maintained by :mkfwd */
static void
printVersion( tOptions* pOpts, tOptDesc* pOD, FILE* fp );
/* = = = END-STATIC-FORWARD = = = */

/*=export_func  optionVersion
 *
 * what:     return the compiled AutoOpts version number
 * ret_type: char const*
 * ret_desc: the version string in constant memory
 * doc:
 *  Returns the full version string compiled into the library.
 *  The returned string cannot be modified.
=*/
char const*
optionVersion( void )
{
    static char const zVersion[] =
        STR( AO_CURRENT.AO_REVISION );

    return zVersion;
}


static void
printVersion( tOptions* pOpts, tOptDesc* pOD, FILE* fp )
{
    char swCh;

    if (pOD->optArg.argString == NULL)
         swCh = 'v';
    else swCh = pOD->optArg.argString[0];

    if (pOpts->pzFullVersion != NULL) {
        fputs( pOpts->pzFullVersion, fp );
        fputc( '\n', fp );

    } else {
        char const *pz = pOpts->pzUsageTitle;
        do { fputc( *pz, fp ); } while (*(pz++) != '\n');
    }

    switch (swCh) {
    case NUL:
    case 'v':
    case 'V':
        break;

    case 'c':
    case 'C':
        if (pOpts->pzCopyright != NULL) {
            fputs( pOpts->pzCopyright, fp );
            fputc( '\n', fp );
        }
        fprintf( fp, zAOV, optionVersion() );
        if (pOpts->pzBugAddr != NULL)
            fprintf( fp, zPlsSendBugs, pOpts->pzBugAddr );
        break;

    case 'n':
    case 'N':
        if (pOpts->pzCopyright != NULL) {
            fputs( pOpts->pzCopyright, fp );
            fputc( '\n', fp );
            fputc( '\n', fp );
        }

        if (pOpts->pzCopyNotice != NULL) {
            fputs( pOpts->pzCopyNotice, fp );
            fputc( '\n', fp );
        }

        fprintf( fp, zAOV, optionVersion() );
        if (pOpts->pzBugAddr != NULL)
            fprintf( fp, zPlsSendBugs, pOpts->pzBugAddr );
        break;

    default:
        fprintf( stderr, zBadVerArg, swCh );
        exit( EXIT_FAILURE );
    }

    exit( EXIT_SUCCESS );
}

/*=export_func  optionPrintVersion
 * private:
 *
 * what:  Print the program version
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + tOptDesc* + pOptDesc + the descriptor for this arg +
 *
 * doc:
 *  This routine will print the version to stdout.
=*/
void
optionPrintVersion( tOptions*  pOpts, tOptDesc*  pOD )
{
    printVersion( pOpts, pOD, stdout );
}

/*=export_func  optionVersionStderr
 * private:
 *
 * what:  Print the program version to stderr
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + tOptDesc* + pOptDesc + the descriptor for this arg +
 *
 * doc:
 *  This routine will print the version to stderr.
=*/
void
optionVersionStderr( tOptions*  pOpts, tOptDesc*  pOD )
{
    printVersion( pOpts, pOD, stderr );
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/version.c */
