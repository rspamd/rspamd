#!/bin/sh 

for d in src src/libserver src/client src/libmime src/libutil src/lua src/classifiers src/tokenizers src/plugins ; do
	file_list=`find ${d} -maxdepth 1 -name "*.c" -or -name "*.h" -type f`
	for file2indent in $file_list
	do 
		echo "Indenting file $file2indent"
		uncrustify -f "$file2indent" -c "./uncrustify.cfg" -o indentoutput.tmp
		mv indentoutput.tmp "$file2indent"
	done
done
