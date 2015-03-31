#include <stdio.h>
#include <glob.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

int globerr(const char *path, int eerrno);
int globdir(char *regex, char *dir);
void crawldir(char *currdir, char *fullpath);
void StripFile(char *currdir, char *filename, long filesize);

int globerr(const char *path, int eerrno)
{
	fprintf(stderr, "%s: %s\n", path, strerror(eerrno));
	return 0;	/* let glob() keep going */
}

int globdir(char *regex, char* dir)
{
	int flags = 0;
	glob_t results;
	int ret;
        int i;

	ret = glob(regex, flags, globerr, & results);
/*	if (ret != 0) {
		fprintf(stderr, "problem with %s (%s), stopping early\n",
			regex,
			(ret == GLOB_ABORTED ? "filesystem problem" :
			 ret == GLOB_NOMATCH ? "no match of pattern" :
			 ret == GLOB_NOSPACE ? "no dynamic memory" :
			 "unknown problem"));
	}*/

	for (i = 0; i < results.gl_pathc; i++) printf("%s/%s\n", dir, results.gl_pathv[i]);
	globfree(& results);
	return 0;
}

void crawldir(char *currdir, char* regex)
{
  DIR *dir;
  struct dirent *de;
  struct stat st;

  chdir(currdir);
  globdir(regex, currdir);
  dir = opendir(".");
  while (de = readdir(dir)) {
    lstat(de->d_name, &st);
    if (S_ISDIR(st.st_mode)) {
      if ((strcmp(de->d_name, ".") != 0) && (strcmp(de->d_name, "..") != 0)) {
        crawldir(de->d_name, regex);
      }
    }
  }
  closedir(dir);
  chdir("..");
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s \"startdir\" \"matching filepattern\"\n", argv[0]);
    fprintf(stderr, "E.g. %s \"/var/www/foo\" \"*.txt\"\n", argv[0]);
    fprintf(stderr, "Description:\t This program ... <snip>.\n");
    fprintf(stderr, "\t\t It recursively crawls its way up startdir. \n");
    return 0;
  }
  crawldir(argv[1], argv[2]);
}
