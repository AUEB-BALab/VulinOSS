#!/bin/bash

input_file=$1
echo "Input file:" $input_file
 
repo_links="$(grep '[^-|\?\?]$' $input_file | cut -f3 -d';')"

while read -r repo; do 
    repo_name="$(echo $repo | cut -f4- -d'/' | tr '/' '_' | sed 's/_$//')"

    if [[ $repo == *".git"* || $repo == *"git."* || $repo == "git:"* ]]; then
        echo "Cloning git $repo_name repository [$repo]"
        git clone $repo $repo_name 2>"$repo_name log.txt"
        echo "finished."
        :
    elif [[ $repo == *".hg"* || $repo == *"hg."* || $repo == *"bitbucket."* || $repo == *"/hg/"* ]]; then
        echo "Cloning mercurial $repo_name repository [$repo]"
        hg clone $repo $repo_name 2>"$repo_name log.txt"
        echo "finished."
        :
    elif [[ $repo == *".svn"* || $repo == *"svn."* || $repo == "svn:"* ]]; then
        echo "Cloning svn $repo_name repository [$repo]"
        svn checkout $repo $repo_name 2>"$repo_name log.txt"
        echo "finished."
        :
    elif [[ $repo == *".cvs"* || $repo == *"cvs."* || $repo == *"//cvs"* ]]; then
        echo "Cloning cvs not yet implemented."
        # cvs checkout -Qd ./ $repo $repo_name
        # echo "finished."
        :
    else 
        echo "Unknown repo: $repo"
    fi

done <<<"$repo_links"