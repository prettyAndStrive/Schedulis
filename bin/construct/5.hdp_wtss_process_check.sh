exec_hosts=$1
web_hosts=$2

ansible_ssh_port=36000
process_check_script=/appcom/Install/AzkabanInstall/wtssdeploy/construct/process_check.sh

result_check(){
  if [ "$?" -ne "0" ];then
    echo $1
    exit 1
  fi;
}


#check wtss exec process exist
#校验wtss exec 进程是否存在
/usr/bin/ansible -i ${exec_hosts}, all -m script -a "${process_check_script} 'azkaban-exec-server'" -e "ansible_ssh_port=${ansible_ssh_port}"
result_check "wtss-exec process does not exist!"

/usr/bin/ansible -i ${web_hosts}, all -m script -a "${process_check_script} 'azkaban-web-server'" -e "ansible_ssh_port=${ansible_ssh_port}"
result_check "wtss-web process does not exist!"

echo "check wtss process success!"
