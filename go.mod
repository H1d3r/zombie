module github.com/chainreactors/zombie

go 1.23.0

require (
	github.com/bradfitz/gomemcache v0.0.0-20230905024940-24af94b03874
	github.com/chainreactors/files v0.0.0-20240716182835-7884ee1e77f0
	github.com/chainreactors/fingers v1.0.1
	github.com/chainreactors/logs v0.0.0-20241030063019-8ca66a3ee307
	github.com/chainreactors/neutron v0.0.0-20250219105559-912bdcebda9a
	github.com/chainreactors/parsers v0.0.0-20240708072709-07deeece7ce2
	github.com/chainreactors/utils v0.0.0-20250109082818-178eed97b7ab
	github.com/chainreactors/words v0.0.0-20241002061906-25d8893158d9
	github.com/denisenkom/go-mssqldb v0.9.0
	github.com/eclipse/paho.mqtt.golang v1.4.3
	github.com/go-ldap/ldap/v3 v3.4.6
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gosnmp/gosnmp v1.32.0
	github.com/hirochachacha/go-smb2 v1.0.10
	github.com/jessevdk/go-flags v1.6.1
	github.com/jlaffaye/ftp v0.0.0-20201112195030-9aae4d151126
	github.com/knadh/go-pop3 v0.3.0
	github.com/lib/pq v1.9.0
	github.com/mitchellh/go-vnc v0.0.0-20150629162542-723ed9867aed
	github.com/panjf2000/ants/v2 v2.4.3
	github.com/samuel/go-zookeeper v0.0.0-20201211165307-7117e9ea2414
	github.com/sijms/go-ora/v2 v2.2.15
	github.com/streadway/amqp v1.1.0
	github.com/vbauerster/mpb/v8 v8.7.2
	go.mongodb.org/mongo-driver v1.12.0
	golang.org/x/crypto v0.36.0
	golang.org/x/net v0.38.0
	sigs.k8s.io/yaml v1.4.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emersion/go-message v0.15.0 // indirect
	github.com/emersion/go-textwrapper v0.0.0-20200911093747-65d896831594 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect
	github.com/go-dedup/megophone v0.0.0-20170830025436-f01be21026f5 // indirect
	github.com/go-dedup/simhash v0.0.0-20170904020510-9ecaca7b509c // indirect
	github.com/go-dedup/text v0.0.0-20170907015346-8bb1b95e3cb7 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358 // indirect
	github.com/icodeface/tls v0.0.0-20190904083142-17aec93c60e5 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe // indirect
	github.com/mozillazg/go-pinyin v0.20.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	github.com/weppos/publicsuffix-go v0.15.1-0.20220329081811-9a40b608a236 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)

require (
	github.com/golang/snappy v0.0.4 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lcvvvv/kscan/grdp v0.0.0-00010101000000-000000000000
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.19.0 // indirect
	github.com/xinsnake/go-http-digest-auth-client v0.6.0
	gopkg.in/yaml.v3 v3.0.1
)

replace (
	github.com/lcvvvv/kscan/grdp => ./external/github.com/lcvvvv/grdp
	golang.org/x/crypto => github.com/golang/crypto v0.23.0
	golang.org/x/text => golang.org/x/text v0.12.0
)
