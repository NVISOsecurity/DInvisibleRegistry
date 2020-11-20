Details on why this poc was released can be found on the following blogpost: 
https://blog.nviso.eu/2020/11/20/dynamic-invocation-in-net-to-bypass-hooks/

This PoC is just to showcase several cool functions of the Dynamic invocation library created as part of the Sharpsploit suite.

``` 
$$$$$$$\  $$\                     $$\           $$\ $$\       $$\           $$$$$$$\                      $$\             $$\
$$  __$$\ \__|                    \__|          \__|$$ |      $$ |          $$  __$$\                     \__|            $$ |
$$ |  $$ |$$\ $$$$$$$\ $$\    $$\ $$\  $$$$$$$\ $$\ $$$$$$$\  $$ | $$$$$$\  $$ |  $$ | $$$$$$\   $$$$$$\  $$\  $$$$$$$\ $$$$$$\    $$$$$$\  $$\   $$\
$$ |  $$ |$$ |$$  __$$\\$$\  $$  |$$ |$$  _____|$$ |$$  __$$\ $$ |$$  __$$\ $$$$$$$  |$$  __$$\ $$  __$$\ $$ |$$  _____|\_$$  _|  $$  __$$\ $$ |  $$ |
$$ |  $$ |$$ |$$ |  $$ |\$$\$$  / $$ |\$$$$$$\  $$ |$$ |  $$ |$$ |$$$$$$$$ |$$  __$$< $$$$$$$$ |$$ /  $$ |$$ |\$$$$$$\    $$ |    $$ |  \__|$$ |  $$ |
$$ |  $$ |$$ |$$ |  $$ | \$$$  /  $$ | \____$$\ $$ |$$ |  $$ |$$ |$$   ____|$$ |  $$ |$$   ____|$$ |  $$ |$$ | \____$$\   $$ |$$\ $$ |      $$ |  $$ |
$$$$$$$  |$$ |$$ |  $$ |  \$  /   $$ |$$$$$$$  |$$ |$$$$$$$  |$$ |\$$$$$$$\ $$ |  $$ |\$$$$$$$\ \$$$$$$$ |$$ |$$$$$$$  |  \$$$$  |$$ |      \$$$$$$$ |
\_______/ \__|\__|  \__|   \_/    \__|\_______/ \__|\_______/ \__| \_______|\__|  \__| \_______| \____$$ |\__|\_______/    \____/ \__|       \____$$ |
                                                                                                $$\   $$ |                                  $$\   $$ |
                                                                                                \$$$$$$  |                                  \$$$$$$  |
                                                                                                 \______/                                    \______/


Old meets new... Persistence is key....

Developed by @jean_maes_1994



 Usage:
  -n, --normal               Uses the regular DInvoke method

  -m, --manual, --manual-map Uses the manualmap method

  -o, --deception            uses the overload method for deception

  -?, --help                 Show Help

  -h, --reg-hide             hide the registry key using null byte magic

  -d, --del, --delreg        deletes given regkey

      --rh, --reg-hive=VALUE the registry hive you want to add a key to
                               (HKLM/HKCU)

      --rs, --reg-sub=VALUE  the subtree you want to open a handle to needs
                               to start with a \ ex. \SOFTWARE

      --rk, --reg-key=VALUE  the name of the registry key you want to write

      --rv, --rkv, --reg-value=VALUE
                             the value of the registry key you want to write

```
