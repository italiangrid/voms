/* Declarations for lexer/parser integration. */
union YYSTYPE;
int yylex();
void yyerror(const char *);
