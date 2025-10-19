qdiscworld-release.sh: qdiscworld.sh
	sed ':again; /\\$$/ { N; s/ *\\\n */ /; t again }' $< > $@
	sed -i -e '/^ *##/d' -e '/^$$/d' $@
