# escape '(' and ')' in folder paths since it's not supported by MinGW
folder=`ls -d \[$1\]*`
echo $folder | sed -e 's/(/\\(/g' | sed -e 's/)/\\)/g'
