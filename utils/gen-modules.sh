#!/bin/sh
#
# This script generate modules.c and modules.h for rspamd
# Used by build system

echo "#ifndef MODULES_H" > modules.h
echo "#include \"config.h\"" >> modules.h
echo "#include \"modules.h\"" > modules.c
echo "module_t modules[] = {" >> modules.c;

for arg in $@ ; do
	IFS=/
	for comp in ${arg} ; do
		echo $comp | egrep '^[^/]+.c$' > /dev/null 2>&1
		if [ $? -eq 0 ] ; then
			mod=`echo $comp | sed -e 's/.c$//'`
		fi
	done
	if [ "F${mod}" != "F" ] ; then
		echo "{\"${mod}\", ${mod}_module_init, ${mod}_module_config, ${mod}_module_reconfig}," >> modules.c
		echo "int ${mod}_module_init(struct config_file *cfg, struct module_ctx **ctx);" >> modules.h
		echo "int ${mod}_module_config(struct config_file *cfg);" >> modules.h
		echo "int ${mod}_module_reconfig(struct config_file *cfg);" >> modules.h
	fi
	IFS=" "
done

echo "};" >> modules.c
echo "#endif" >> modules.h
