# tonos_cli_ruby_methods

Ruby methods for tonos cli

## Usage

include TonosCli



TonosCli.network_url = 'https://main.ton.dev'

TonosCli.hostname = `echo $(hostname -s)`&.chomp

TonosCli.user = `whoami`&.chomp

TonosCli.ton_script_dir = "/home/#{TonosCli.user}/ton/main.ton.dev/scripts"

TonosCli.run_script_dir = "~/tonos-run" - folder with all abi.json and tvc files

TonosCli.keys_folder_dir = "~/keys" - folder with all keys

--------


p get_depool_participants_info(depool_addr, "#{TonosCli.run_script_dir}/DePool.abi.json")
