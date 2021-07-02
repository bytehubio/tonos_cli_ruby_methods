require "set"
require "json"
require "byebug"

module TonosCli
  def self.class_attr_accessor(*names)
    names.each do |name|
      class_variable_set("@@#{name.to_s}", nil)

      define_singleton_method("#{name.to_s}=".to_sym) do |attr|
        class_variable_set("@@#{name.to_s}", attr)
      end
      
      define_singleton_method(name.to_sym) do
        class_variable_get("@@#{name.to_s}")
      end
    end
  end

  class_attr_accessor :network_url, :ton_folder_dir, :hostname, :user, :ton_script_dir, :run_script_dir, :keys_folder_dir
end


TonosCli.hostname = `echo $(hostname -s)`&.chomp
TonosCli.user = `whoami`&.chomp

# TonosCli.network_url = 'https://main.ton.dev'
# TonosCli.ton_folder_dir = `echo $TON_FOLDER_DIR`&.chomp
# TonosCli.ton_script_dir = "/home/#{TonosCli.user}/ton/main.ton.dev/scripts"
# TonosCli.run_script_dir = "/home/#{TonosCli.user}/source/tonos-run"
# TonosCli.keys_folder_dir = "/home/#{TonosCli.user}/source/tonos-run/keys"






module TonosCli
  
  def tonoscli(network=nil, params)
    network = TonosCli.network_url unless network
    `tonos-cli --url #{network} #{params}`
  end

  def genphrase
    out = tonoscli("genphrase")
    if out[/Seed phrase:.*"(.+)".*$/]
      phrase = $1
      return phrase
    end
    ''
  end

  def getkeypair(name, phrase=nil)
    unless phrase
      phrase = genphrase
    end
    unless phrase.empty?
      `cd #{TonosCli.run_script_dir} && echo '#{phrase}' >> #{name}_phrase.txt`
      tonoscli(%{getkeypair #{name} "#{phrase}"})
      return true
    end
    false
  end

  def get_keys_and_phrase
    phrase = genphrase
    random_name = "#{Random.srand()}_keys"
    tonoscli(%{getkeypair #{random_name} "#{phrase}"})
    keys = JSON.parse(File.read("#{TonosCli.run_script_dir}/#{random_name}"))
    FileUtils.rm_f("#{TonosCli.run_script_dir}/#{random_name}")
    {
      phrase: phrase,
      keys: {
        public: keys["public"],
        secret: keys["secret"]
      }
    }
  end

  # GEN WALLET ADDRESS
  def genaddr(tvc, abi, msig, wc=0)
    out = tonoscli("genaddr #{tvc} #{abi} --setkey #{msig} --wc #{wc}")
    if out[/Raw address:\s*(.+)\s*$/]
      address = $1
      return address
    end
    ''
  end

  def gen_full_addr(tvc, abi, wc=0)
    keys_and_phrase = get_keys_and_phrase
    random_name = "#{Random.srand()}_keys"
    dir = "#{TonosCli.run_script_dir}/#{random_name}"
    File.write(dir, %{{"public": "#{keys_and_phrase[:keys][:public]}", "secret": "#{keys_and_phrase[:keys][:secret]}"}}, mode: "w")
    out = tonoscli("genaddr #{tvc} #{abi} --setkey #{dir} --wc #{wc}")
    FileUtils.rm_f(dir)
    address = ''
    if out[/Raw address:\s*(.+)\s*$/]
      address = $1
      keys_and_phrase[:address] = address
    end
    keys_and_phrase
  end

  # account
  def account(wallet_addr)
    out = tonoscli("account #{wallet_addr}")
    if out[/balance:\s+(\d+).*$/]
      balance = $1
      return balance.to_i
    end
  end

  def account_status(wallet_addr)
    out = tonoscli("account #{wallet_addr}")
    if out[/acc_type:\s+(\w+).*$/]
      status = $1
      return status
    end
    ''
  end

  def run_method(addr, method, abi, json='{}')
    tonoscli("run #{addr} #{method} '#{json}' --abi #{abi}")
  end

  # submitTransaction
  def submitTransaction(from, to, tokens, msig="#{TonosCli.keys_folder_dir}/msig.keys.json", bounce=false, all_balance=false, payload='', abi="#{TonosCli.run_script_dir}/SafeMultisigWallet.abi.json")
    tokens = (tokens * 1000000000).to_i
    tonoscli("call #{from} submitTransaction '{\"dest\":\"#{to}\",\"value\":#{tokens},\"bounce\":#{bounce},\"allBalance\":#{all_balance},\"payload\":\"#{payload}\"}' --abi #{abi} --sign #{msig}")
  end

  def submitJsonTransaction(from, json={}, msig="#{TonosCli.keys_folder_dir}/msig.keys.json", abi="#{TonosCli.run_script_dir}/SafeMultisigWallet.abi.json")
    json[:value] = (json[:value] * 1000000000).to_i
    tonoscli("call #{from} submitTransaction '#{json.to_json}' --abi #{abi} --sign #{msig}")
  end

  # sendTransaction -> ТОлько если один кастодиан 
  # "flags": 3 "платить комиссию с кошелька отправителя" + "игнорировать ошибки" они по дефолту ставятся в submitTransaction
  # "flags": 160 - вывести весь баланс, кошелек становится неактивным, value должно быть 0
  def sendJsonTransaction(from, json={}, msig="#{TonosCli.keys_folder_dir}/msig.keys.json", abi="#{TonosCli.run_script_dir}/SafeMultisigWallet.abi.json")
    json[:value] = (json[:value] * 1000000000).to_i
    tonoscli("call #{from} sendTransaction '#{json.to_json}' --abi #{abi} --sign #{msig}")
  end

  def confirmTransaction(wallet_addr, transaction_id, msig="#{TonosCli.keys_folder_dir}/msig.keys2.json", abi="#{TonosCli.run_script_dir}/SafeMultisigWallet.abi.json")
    tonoscli("call #{wallet_addr} confirmTransaction '{\"transactionId\":\"#{transaction_id}\"}' --abi #{abi} --sign #{msig}")
  end

  # confirmTransactions
  def confirmTransactions(wallet_addr, msig="#{TonosCli.keys_folder_dir}/msig.keys2.json")
    transactions_resp = getTransactions(wallet_addr)
    transactions_resp["transactions"].each { |transaction| p confirmTransaction(wallet_addr, transaction['id'], msig) }
  end

  # getTransactions
  def getTransactionsRaw(wallet_addr, abi="#{TonosCli.run_script_dir}/SafeMultisigWallet.abi.json")
    tonoscli("run #{wallet_addr} getTransactions {} --abi #{abi}")
  end

  # getTransactions json
  def getTransactions(wallet_addr)
    out = getTransactionsRaw(wallet_addr)
    if out[/Result:([\s\S]+)$/]
      json = $1
      return JSON.parse(json || '{}')
    elsif out[/Error:([\s\S]+)$/]
      error = $1
      raise error
    end

    {"transactions" => []}
  end

  def get_depool_info(depool_addr, abi)
    info = tonoscli("run #{depool_addr} getDePoolInfo {} --abi #{abi}")
    raise $1 if info[/Error(.+)/]
    result = {}
    info.gsub!(/\n/, '')
    info[/Result\s*:\s*(\{[\s\S]+\})/]
    json = $1
    JSON.parse(json || '{}')
  end

  def get_depool_participant_info(depool_addr, abi, participant_addr)
    info = tonoscli(%{run #{depool_addr} getParticipantInfo '{"addr":"#{participant_addr}"}' --abi #{abi}})
    raise $1 if info[/Error(.+)/]
    result = {}
    info.gsub!(/\n/, '')
    info[/Result\s*:\s*(\{[\s\S]+\})/]
    json = $1
    JSON.parse(json || '{}')
  end

  def get_depool_participants(depool_addr, abi)
    info = tonoscli(%{run #{depool_addr} getParticipants {} --abi #{abi}})
    raise $1 if info[/Error(.+)/]
    result = {}
    info.gsub!(/\n/, '')
    info[/Result\s*:\s*(\{[\s\S]+\})/]
    json = $1
    JSON.parse(json || '{}')
  end

  def get_depool_participants_info(depool_addr, abi)
    result = []
    participants = get_depool_participants(depool_addr, abi)['participants'] || []
    participants.each do |participant_addr|
      participant_info = get_depool_participant_info(depool_addr, abi, participant_addr)
      participant_info['addr'] = participant_addr
      result << participant_info
    end
    result
  end

  def get_depool_participants_stakes(depool_addr, abi)
    result = []
    participants = get_depool_participants(depool_addr, abi)['participants'] || []
    participants.each do |participant_addr|
      participant_info = get_depool_participant_info(depool_addr, abi, participant_addr)
      info = {
        'addr' => participant_addr,
        'total' => participant_info['total'].to_f / 1000000000,
        'reinvest' => participant_info['reinvest'],
        'reward' => participant_info['reward'].to_f / 1000000000, 
        'stakes' => Hash[participant_info['stakes'].map{|k, val| [k, (val.to_f / 1000000000)] } ]
      }
      result << info
    end
    result
  end

  def print_depool_participants_stakes(depool_addr, abi)
    get_depool_participants_stakes(depool_addr, abi).each { |pr| p "#{pr['addr']} - t: #{pr['total']} - rew: #{pr['reward']}" }
  end

  def deploy_sc(tvc, abi, json, msig="#{TonosCli.keys_folder_dir}/msig.keys.json", wc=0)
    tonoscli("deploy #{tvc} '#{json}' --abi #{abi} --sign #{msig} --wc #{wc}")
  end

  def deploy_wallet(keys, confirmations, tvc_dir="#{TonosCli.run_script_dir}/SafeMultisigWallet.tvc", abi="#{TonosCli.run_script_dir}/SafeMultisigWallet.abi.json", msig="#{TonosCli.keys_folder_dir}/msig.keys.json", wc=0)
    raise 'NOT KEYS' if keys.empty?
    json = "{\"owners\": [\"#{keys.join('", "')}\"],\"reqConfirms\":#{confirmations}}"
    deploy_sc(tvc_dir, abi, json, msig, wc)
  end

  def deploy_de_pool(minStake: nil, validatorAssurance: nil, proxyCode: nil, validatorWallet: nil, participantRewardFraction: nil, tvc: "#{TonosCli.run_script_dir}/DePool.tvc", abi: "#{TonosCli.run_script_dir}/DePool.abi.json", msig: "#{TonosCli.keys_folder_dir}/depool.json", wc: 0)
    json = %{{"minStake":#{minStake}, "validatorAssurance":#{validatorAssurance}, "proxyCode":"#{proxyCode}", "validatorWallet":"#{validatorWallet}", "participantRewardFraction":#{participantRewardFraction}}}
    deploy_sc(tvc, abi, json, msig, wc)
  end

  def deploy_helper(depool_addr, msig="#{TonosCli.run_script_dir}/helper.json", wc=0, tvc="#{TonosCli.run_script_dir}/DePoolHelper.tvc", abi="#{TonosCli.run_script_dir}/DePoolHelper.abi.json")
    json = %{{"pool":"#{depool_addr}"}}
    deploy_sc(tvc, abi, json, msig, wc)
  end

  def configure_depool_helper(helper_addr, timer, period_sec, abi="#{TonosCli.run_script_dir}/DePoolHelper.abi.json", msig="#{TonosCli.run_script_dir}/helper.json")
    json = %{{"timer":"#{timer}","period":#{period_sec}}}
    tonoscli("call #{helper_addr} initTimer '#{json}' --abi #{abi} --sign #{msig}")
  end

  def decode_tvc(tvc_path)
    tvm = `tvm_linker decode --tvc #{tvc_path}`
    result = {}
    while tvm[/([^\n]+?):([\s\S]+?)$/]
      key = $1.strip
      val = $2.strip
      result[key] = val
      tvm.sub!(/([\s\S]+?):([\s\S]+?)$/, '')
    end
    result
  end

  def tickTock(depool_helper_addr, depool_addr, abi, sign)
    tonoscli("call #{depool_helper_addr} sendTicktock {} --abi #{abi} --sign #{sign}")
  end

  def multisigTickTock(main_wallet, depool_addr, sign, sign2=nil)
    # depool [--addr <depool_address>] ticktock [-w <msig_address>] [-s <path_to_keys_or_seed_phrase>]
    tonoscli("depool --addr #{depool_addr} ticktock -w #{main_wallet} -s #{sign}")
    confirmTransactions(main_wallet, sign2) if sign2
  end

  def ordinary_stake(value, depool_addr, wallet_addr, sign)
    reinvest(depool_addr, wallet_addr, sign, reinvest: true)
    tonoscli("depool --addr #{depool_addr} stake ordinary --wallet #{wallet_addr} --value #{value} --sign #{sign}")
  end

  def terminate_depool(depool_addr, depool_abi, sign)
    tonoscli("call #{depool_addr} terminator {} --abi #{depool_abi} --sign #{sign}")
  end

  def reinvest(depool_addr, wallet_addr, sign, reinvest={reinvest: false})
    tonoscli("depool --addr #{depool_addr} withdraw #{reinvest[:reinvest] ? 'off' : 'on'} --wallet #{wallet_addr} --sign #{sign}")
  end

  def withdraw_part_stake(depool_addr, main_wallet, value, sign)
    tonoscli("depool --addr #{depool_addr} stake withdrawPart --wallet #{wallet_addr} --value #{value} --sign #{sign}")
  end

  def withdraw_all(depool_addr, wallet_addr, sign)
    reinvest(depool_addr, wallet_addr, sign, reinvest: false)
  end
end













module TonosCli
  module Rust

    include TonosCli

    def get_info_from_elector_rust(abi_dir)
      out = run_method("-1:3333333333333333333333333333333333333333333333333333333333333333", 'get', abi_dir, {})
      out[/Result:([\s\S]+)$/]
      f = $1
      raise 'active_election_id returned NIL' unless f
      f.gsub!(/\n/, '').strip!
      JSON.parse(f)
    end
  end
end














module TonMethods

  def getconfigs
    result = {}
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -rc 'getconfig 17' -rc 'quit' 2>/dev/null`

    out[/min_stake.+\n.+value[^\d]+(\d+)/]
    result[:min_stake] = $1.to_i / 10**9

    out[/min_stake.+\n.+value[^\d]+(\d+)/]
    result[:min_stake] = $1.to_i / 10**9
    
    out[/max_stake.+\n.+value[^\d]+(\d+)/]
    result[:max_stake] = $1.to_i / 10**9

    out[/min_total_stake.+\n.+value[^\d]+(\d+)/]
    result[:min_total_stake] = $1.to_i / 10**9

    out[/max_stake_factor[^\d]+(\d+)/]
    result[:max_stake_factor] = $1&.to_i&.to_s(16)&.to_i

    result
  end

  def get_ballance
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -rc 'getaccount -1:428c93d1dad5fe1f3e1bf19e42939891bcf44f02bfd90fbcaa24bbbd9c4446bb' -rc 'quit' 2>/dev/null | grep 'balance is'`
    if out[/(\d+)/]
      ballance = $1
      return ballance.to_i / 10**9
    end
  end

  def get_past_elections_weights
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -c 'getconfig 32' -rc 'quit' 2>/dev/null`
    # public_key:(ed25519_pubkey pubkey:x515126BBFAC9E55A0472832E483E0C41C5680A724590314675713FD061F76972) weight:2842041853755831 adnl_addr:x9CE73BB45BB28D463CF21A3B694076DE2FE7E2102FB8DA1CC400F0FA27DE6578)

    result = {}
    total_weight = 0
    loop do
      out.sub!(/public_key.+pubkey[^\w]+(\w+).+weight[^\d](\d+).+adnl_addr[^\w]+(\w+)/, '')
      public_key = $1
      weight = $2
      adnl_addr = $3
      break if !weight
      total_weight += weight.to_i
      result[public_key] = {
        weight: weight.to_i,
        adnl_addr: adnl_addr
      }
    end
    
    result.each do |pub_key, item| 
      result[pub_key][:total_weight] = total_weight
      result[pub_key][:percent_weight] = item[:weight] / total_weight.to_f
    end
    
    result
  end

  def get_current_elections_weights
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -c 'getconfig 34' -rc 'quit' 2>/dev/null`
    # public_key:(ed25519_pubkey pubkey:x515126BBFAC9E55A0472832E483E0C41C5680A724590314675713FD061F76972) weight:2842041853755831 adnl_addr:x9CE73BB45BB28D463CF21A3B694076DE2FE7E2102FB8DA1CC400F0FA27DE6578)

    result = {}
    total_weight = 0
    loop do
      out.sub!(/public_key.+pubkey[^\w]+(\w+).+weight[^\d](\d+).+adnl_addr[^\w]+(\w+)/, '')
      public_key = $1
      weight = $2
      adnl_addr = $3
      break if !weight
      total_weight += weight.to_i
      result[public_key] = {
        weight: weight.to_i,
        adnl_addr: adnl_addr
      }
    end
    
    result.each do |pub_key, item|
      result[pub_key][:total_weight] = total_weight
      result[pub_key][:percent_weight] = item[:weight] / total_weight.to_f
    end
    
    result
  end

  def get_past_elections_total_stake
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -c 'runmethod -1:3333333333333333333333333333333333333333333333333333333333333333 past_elections' -rc 'quit' 2>/dev/null`
    out[/result:\s+\[.+\s+.+\s+.+\s+.+\s+.+\s+(\w+)\s+.+\s+.+\]/]
    total_stake = $1
    total_stake&.to_i
  end

  def get_participant_list
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -c 'runmethodfull -1:3333333333333333333333333333333333333333333333333333333333333333 participant_list' -rc 'quit' 2>/dev/null`
    # [115174162090671863133723081646835925774865477576557164333468186485495213520177 16255000000000]

    result = []
    loop do
      out.sub!(/\[\s*(\d+)\s+\[(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]\s*\]/, '')
      id = $1
      stake = $2
      max_factor = $3
      addr = $4
      adnl_addr = $5
      break if !id
      result << {
        id: id, 
        stake: stake,
        max_factor: max_factor.to_i.to_s(16).to_i,
        addr: addr.to_i.to_s(16),
        adnl_addr: adnl_addr.to_i.to_s(16)
      }
    end

    result
  end

  def get_participant_list_extended
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -c 'runmethodfull -1:3333333333333333333333333333333333333333333333333333333333333333 participant_list_extended' -rc 'quit' 2>/dev/null`
    # unless out[/\[\s*(\d+)\s+\[(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]\s*\]/]
    #   raise 'participant_list_extended not works'
    # end
    # [115364769381711985676191404797531085158836848200337250445608490943598037098294 [10000000000000 196608 65285866190926269223588609262902744863930007113865173951504909034489155844542 9270661424391099987945973191613458068238496810249389371829447331302709193273]]
    # [id, [stake, max_factor, addr, adnl_addr]]
    result = []
    loop do
      out.sub!(/\[\s*(\d+)\s+\[(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]\s*\]/, '')
      id = $1
      stake = $2
      max_factor = $3
      addr = $4
      adnl_addr = $5
      break if !id
      result << {
        id: id, 
        stake: stake,
        max_factor: max_factor.to_i.to_s(16).to_i,
        addr: addr.to_i.to_s(16),
        adnl_addr: adnl_addr.to_i.to_s(16)
      }
    end

    result
  end

  def addr_without_wc(wallet_addr)
    if wallet_addr[/^(.+):(.+)/]
      wallet_addr = $2
    end
    wallet_addr.sub!(/^0+/, '')
    # wallet_addr.sub!(/0+$/, '')
    wallet_addr
  end

  def present_in_participant_list?(wallet_addr)
    wallet_addr = addr_without_wc(wallet_addr)
    list = get_participant_list_extended
    list.each_with_index do |i, index|
      if i[:addr] == wallet_addr
        return true
      end
    end
    false
  end

  def present_in_participant_depool?(proxies)
    proxies = proxies.map { |proxy| addr_without_wc(proxy)}
    list = get_participant_list_extended
    list.each_with_index do |i, index|
      if proxies.include?(i[:addr])
        return true
      end
    end
    false
  end

  def compute_returned_stake(wallet_addr)
    wallet_addr = addr_without_wc(wallet_addr)
    wallet_addr = "0x#{wallet_addr}"
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -a 127.0.0.1:3031 -C /var/ton-work/etc/ton-global.config.json -v 0 -c 'runmethod -1:3333333333333333333333333333333333333333333333333333333333333333 compute_returned_stake #{wallet_addr}'`
    # result:  [ 0 ] 
    out[/result:\s+\[\s*(\d+)\s*\]/]
    nano_stake = $1
    nano_stake.to_i
  end

  # unix time окончание цикла выборов
  def active_election_id
    out = `#{TonosCli.ton_folder_dir}/ton/build/lite-client/lite-client -p /home/#{TonosCli.user}/ton-keys/liteserver.pub -C /var/ton-work/etc/ton-global.config.json -a 127.0.0.1:3031 -rc 'runmethod -1:3333333333333333333333333333333333333333333333333333333333333333 active_election_id' -rc 'quit' 2>/dev/null`
    # result:  [ 0 ]
    out[/result:\s+\[\s*(\d+)\s*\]/]
    nano_stake = $1
    nano_stake.to_i
  end

  # nanotokens - 10^9
  def send_tokens_to_elector(wallet_addr, tokens, abi="#{TonosCli.ton_folder_dir}/configs/SafeMultisigWallet.abi.json", msig="/home/#{TonosCli.user}/ton-keys/msig.keys.json")
    tokens = (tokens.to_i * (10**9)).to_i
    boc = `cd ~/ton-keys/elections && echo $(base64 --wrap=0 "validator-query.boc")`&.chomp
    tonoscli(%{call #{wallet_addr} submitTransaction '{"dest":"-1:3333333333333333333333333333333333333333333333333333333333333333","value":"#{tokens}","bounce":true,"allBalance":false,"payload":"#{boc}"}' --abi #{abi} --sign #{msig}})
  end

  def send_nanotokens_to_elector(wallet_addr, nanotokens, abi="#{TonosCli.ton_folder_dir}/configs/SafeMultisigWallet.abi.json", msig="/home/#{TonosCli.user}/ton-keys/msig.keys.json")
    boc = `cd ~/ton-keys/elections && echo $(base64 --wrap=0 "validator-query.boc")`&.chomp
    tonoscli(%{call #{wallet_addr} submitTransaction '{"dest":"-1:3333333333333333333333333333333333333333333333333333333333333333","value":"#{nanotokens}","bounce":true,"allBalance":false,"payload":"#{boc}"}' --abi #{abi} --sign #{msig}})
  end
end























