#include "argument.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ARGUMENT_DELETE_REST
/* #define ARGUMENT_DELETE_REST */
#endif

static const char * delete_arg(int * argcp, char * argv[], int i)
{
  const char * ret;
  if (i > *argcp - 1) return (NULL);
  ret = argv[i];
  (*argcp)--;
  for (; i < *argcp; i++)
    argv[i] = argv[i + 1];
  return (ret);
}

static const Argument * check_arg(int argc, char * argv[], int i,
				  const Argument * args)
{
  if (i > argc - 1) return (NULL);
  for (; args->name; args++)
    if (!strcmp(argv[i], args->name))
      return (args);
  return (NULL);
}

int argument_read(int * argcp, char * argv[], const Argument argument[])
{
  int i;
  const char * p;
  int n = 0;
  const Argument * arg;

  for (i = 1; i < *argcp; i++) {
    while ((arg = check_arg(*argcp, argv, i, argument)) != NULL) {
      delete_arg(argcp, argv, i);
      n++;
      switch (arg->type) {
      case ARGUMENT_TYPE_NONE:
	/* None */
	break;
      case ARGUMENT_TYPE_FUNCTION:
	((void (*)())(arg->value))();
	break;
      case ARGUMENT_TYPE_FLAG_ON:
	*((int *)(arg->value)) = ARGUMENT_FLAG_ON;
	break;
      case ARGUMENT_TYPE_FLAG_OFF:
	*((int *)(arg->value)) = ARGUMENT_FLAG_OFF;
	break;
      case ARGUMENT_TYPE_INTEGER:
	p = delete_arg(argcp, argv, i);
	if (p) *((int *)(arg->value)) = atoi(p);
	break;
      case ARGUMENT_TYPE_FLOAT:
	p = delete_arg(argcp, argv, i);
	if (p) *((double *)(arg->value)) = atof(p);
	break;
      case ARGUMENT_TYPE_STRING:
	p = delete_arg(argcp, argv, i);
	if (p) *((const char **)(arg->value)) = p;
	break;
      }
    }
  }

#ifdef ARGUMENT_DELETE_REST
  while (*argcp > 1) {
    fprintf(stderr, "ERROR : Unknown Argument : %s\n", argv[1]);
    delete_arg(argcp, argv, 1);
  }
#endif

  return (n);
}
