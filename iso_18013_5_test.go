package mdoc

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/veraison/go-cose"
)

const (
	EDeviceKeyX = "5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe"
	EDeviceKeyY = "b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
	EDeviceKeyD = "c1917a1579949a042f1ba9fc53a2df9b1bc47adf31c10f813ed75702d1c1f136"

	EReaderKeyX = "60e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e"
	EReaderKeyY = "e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa"
	EReaderKeyD = "de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c"

	DeviceEngagementHex = "a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa" +
		"444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6702818" +
		"30201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917"

	SessionEstablishmentHex = "a26a655265616465724b6579d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999" +
		"c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67bec" +
		"cdfa64646174615902df52ada2acbeb6c390f2ca0bc659b484678eb94dd45074386aadece23777b44606e42e" +
		"2846bc2e2ee3c1e867b1d1685e41354a021abb0fda36f09cf5d5c51b561d3be41c9347ae71cf2b49de9dec7b4" +
		"4046ab02247931b210c9157840c1514a6027b08810716adf61966344979314ac3ae9f40e66e015c1254a68410" +
		"8bd093e8772ec333fb663fd6803af02ea10bdbe83a999f75b55a180f872139fb57ac04acd58ca15eca150cde1c" +
		"3b849401188b7a30ce887dd7b71b12eda2fc6ec6e5235a6c9498351fcd301f2292a4ebba7555285cee84ead96e" +
		"f1677b0af8239f6a7a52af4b8809b1d52ab21a162ca31ade21c57bd1d9970a2832aac41c7d52d1c4fee4ee6403" +
		"0a218df51363be701792fa6c515c489bd39dcad6fba48f1d6eb19e9c769531a3bf9998a32c01841305f23844ca" +
		"3db6a1ff0d0d917343d62fc72ad58eab01a3198116f19606609f94e35eacb78d23c59c67852a361915fe87848c" +
		"dba5630c99fab71aeff72d131cf442654f7708ec48216416f2d996cf6cf91012b771b88907b1d1629dfa794343e" +
		"653c31207482e2f6621cd4b5dcf3b3c328625c33fe98be99c5f264a264315be41bafdc726f8bcde5920de0a718" +
		"84d860af44c1ff1b3d78b2e8d720d85dae53fea2b3fa1806162a4be02d039567c5eb2419c2ad879af48fcb7df55" +
		"ca94f1b00f62187fa2329c8227aae0130ec052ca3e2102e57e72911b328cfdcfbaaf6b9364660f613415382644" +
		"c30c0bd4e222c5cf94ba5a73679c53d5ced95ca50787c2289a0c17358393c1e0f2272361002fb9b160606888a5" +
		"9ef7a2c389f68b7cb424572db026b17cf2bdcafcb67c8292d92b50050356900a62a82b16f854759052b00f0f46" +
		"73a46229f43257e8e8325401b3fecc8c6d2258baf7f7c2fbbafab3a1b6aded4eceac1eafd5b61118df93bc0a62" +
		"2b03504fde47cebb224e983db12677e316c22aae042d6ce4adae0d8b0f40437b8e1afa0859c9501beb63974496" +
		"859a60f11069b1965b4ffac5779a96191f89eac7caa688b9e67c"

	SessionDataHex = "a16464617461590dfa46da5fb292a7880af38f2e4d9eb23ecac231ad21dfe81e3b5c21e7f3d2b5a2d4676dd13" +
		"331112f0fba678275dc2fcd889150a7bbb333b7ecf5f35fc8b2e4aee701651a4bdc93cd25bc533582647507b5" +
		"b9a075deaf7e1ef035acb3c8b403ac6e51a19d4289381035199da169b5ab175d8bc2075ac73dbaa76aa79d9a2" +
		"6ac3930034515525c413110abaeae731545b36400205f3130e902242db99066a04ab6cef9d14672c3dfe46780" +
		"2e5364dff5535c8c36fdb53afde285ee9462f72a4f8b5707879590d8b5ee83a3068c1c25f13681085cf4a5af3c" +
		"b2e77bcc7cae6def76ab5ad119e6db563799d15af9f5861b7ec0003c68fa46f12ca366263b5fe5bb8f5b16bede" +
		"1e5e5919abf8b675fb10ce4655815fe6a3582ec44e0c93f0cf3a5ea1ca2e476113b47bc1ff2484f791c68385cd" +
		"5ff3f1f27f70a88c7c649581e59a5bb2371d6268704526bf1b16cd36d9e739bef50a199deafb8ceadd42c260e5" +
		"8688bd569b420f32ad0502e6dff9346440459febbb49d843e50e93d46c0fd2125d4131e1d528435110b5e0db9e" +
		"41795716422dc895425773eae490fbfba7c10f85ec364bdfac7de120ba4883142e854bf19510f969be690fad9" +
		"a3f7197885dcb44bd9028998adf6e95356af058e4c20502b5c4d3c4c52469727042e75e0ca8e43efb590da9a1a" +
		"1cc3ffdd03a422e7589ec237c36c0d5587ab853ab39be4388cdd9feb7b763ecb6344172fafde86a9501975dd86f" +
		"19f095f98a1e65ace933e8723db8f1e5074f7c9c0415e4e69f12c2a6c14c0ca09c872f2ac83e0ec7294e6dc4f1" +
		"fa087d48201c9c68d1cef4b793fb97b374505b348e090207a179305347599060200a1f398e9d9aa2eadbe31ee0" +
		"172b25d1f0b1287b3aad8f1afa560981c6490a1aec1052f47201ab5baed0ecf826c7b2b416ce0c2e265403a922" +
		"f80d1cf6842a7182c8bbe7a138096cb1fcffcfc102d16d08cbf86108393ef8276120e9341c11c5e5e1cebc257b6" +
		"97d2182ed1ead67d7e5814a3f9b380cf917ccf59921f4ae545a14a8ec0f8642b7bd5565039b60546efb2c68aa" +
		"0ac2d3f972386cd9f47280e2f27af727335cd6ca1aec25c2ad2d079cd3fb045ccbaf6f4a5b0a80e07795f5790f" +
		"f53aaefdf3a63240ca7e9d5658ce84a21d310463335cf1f6015dc89ee54d687abcd4787c060a0bce53020b1c6a" +
		"5bb6c3ea4d759b7f3eddabcaade785c23caa9ba15272724e0589cef502d80085bd77bae93897b01e2588ddd504" +
		"aebe8333a153790a9699748a4269f5017c81aaf8061f9985e0cf7553b4c4d0a5c401f20f0ab6d85078728676bc" +
		"fdc9c1a1bc4dea2b01c68e0bb7bf8ada66aa93fc322673efa3895b09d085a0cd085dab3018a9e032acd3d715bf" +
		"190c629fc55d55ed815b0ba56e83f78c453165c024ca5b2de5b4accfbab07aa1c482b8e960db03652167f903db" +
		"0ecf03ef85834951a603c3e6069210744d70c5875e50badb91dcc8beca4945b869e73e535a7967fbcb377ce86" +
		"1f07e537349c8a33793c0c05c1b4dd220634e1f52f6701d79d83f99311d6c1463ea3bbcf4d1a7614cbedfceaf" +
		"a1e874b84e6b30698551c6da9f8487fc5270cd5dc73f9aa9dc8a513b1514d7abb0bec4d2cd06b14efd23f3c596" +
		"02fcfc5d9aecf48148128ca86d6d4ebbe2f68460db00a49759887a478a1eccdd8b426aa130d8b7da0e331415a9" +
		"682d7125e56285a927f54ac5139a3f8d78c2dc6ffa0bc9ad4db749e8dae10169aa6be9206b635943b7a0970a23e" +
		"04a2ba66712365b2ea0afb0422a0224592074f723781b8df86627296f9f126f94efe089f8db5f2eea4f28673e1" +
		"1ccd80726901ee1bcc8fa49b6f65c0f8587222f2bb81744a3ece2f74ac21e8c5805d054f93e2d669616ecbc07" +
		"f3d017a36b951aecd28a14ada87e4f935ef7f93c2c7d01cedf5658131908e4d36aa4690ba952d3f7fa25b6a848" +
		"1d42f6a7794c8b1dd4de2f7e6bb3ed6fd3915591997e06f01715bac3cdfb0885ce97136e4b7b4b1e6685fd42de" +
		"1e8ae610523c2b2603977cf3c45058802d734322a9aa0181ff1231b4674071e5c75d8f11e56d67916b4d5f7a9b4" +
		"2a26519c990fdb728630f0755cf8fc0d177c24e1375cc793cee463da5dbef1fe6a835bf75317052b7b077d397c" +
		"7b617a632371d22eb64c91f91d8fdf5aa3345f0e6e7a0d42e8da52087a89428a1241b4527d5f4d3751b10d40e8" +
		"768bc6b1a55b531a9e8fb9afdfaf3aed0a3bc71b9c432b89da34e4685b8b48f650394e760270df2c837ab51ded" +
		"999b903c0f9630478adb8843e462ad8123466ff837dc18241db341ecabbc0a8693bd35831d49c09adf8c5d7c4f8" +
		"0b3628b633d46a93c2b7b61e5127abb5e877e6904de7049a53213b357cdb443c31bababdc0480fe6986951ea9d" +
		"684e53f5b53871e80148afc30c4e2eed05a0aeafa0b98f98e8ffbad6af968ecfd286b24c43bf2b54e64e28fab32" +
		"8d791bbf80292e2226dfc7d0d562b511321b6b501eadbd1661f028bad02e37575104f646222484aac1548a762" +
		"cfec36b9597a4e7309497b49f1921a948a597cc7d721f6396389aaffd2828da0443e4f2354cf2fbe69c0a2a8f3" +
		"d2271207440e95445a4fb24de95d5232e66ff84c8e1ab5c5576e316ce3e78d7c0047695ef0037cc7f7d0f21fa5" +
		"3a1976a7e1bb2d70751c6ebebb5fd24dad9fa58ffee261b0ee7a55a86a6236901feb322400965313175a263e5b" +
		"8437eb2a7ddf239d15c27b2e8b55abccd7574df807f3e8483670aac580fec1bbeb779a3cb2e89440e8badccdc" +
		"dccf6f6e7dd9a2d62080c7057824ede7186f924e2c59934a0fc0d518d05ff48da1b012322bb55d2493a850954b" +
		"6af585e72f5bef55180f9fc293e40bd48a261cee4099ad4674541ddb5a81683034e9e31f59c8942321f09a5ed1" +
		"e11854b6cd8af4afcf919f2001722c2396b9b30e1c5d8182061bb39201477a0538db896a399493151b1f616228" +
		"4284b8cc42701fad81c63846f0d7e3be5004a3d1e5dc047c2b28d7c28940e70ba52ac7aa0de584a9ff7859aa0e9" +
		"af8d24d5dcfd07cf5c6fd8034e2a3ef63b41be59ab93d941cee00b3029478181e576d3b0c09f28b1c70ab7c2e6" +
		"22e7cacb2f6d2337c430afa5736169bddfe379f5b3d3392cfaa1bc45f6d3e47e73678ec19cecb20b3aee82378e" +
		"41f84b59c172abc8d40370f8bb833f8edca890cd4f85f5610d3e208bada4deb6f15d9cb0a9f805b1f9915e40be" +
		"d12ed2494886801d6ff83df037b4a245d03489fa7dda552dccbd11b84101c4147595e0ee6d89b5d7621492d21dc" +
		"01b5afc1ce3c65cc878d823810f7d0c4232374a4e82013ad3a99f2422aa8e4e2cc33c66dc5b07bd2ece4169995" +
		"63a6f2e62ef367904990f1442519eb00c6eecb1c886bde5613dba37908cc79f71bcfbf5fb96142488f0be69c51" +
		"0e144bd1a25f2e6f22bf78cc213d7ba83def9146224b67c1ca5cad8520e55d1b01daaa70475caa1e4ed117ac8" +
		"952a3f4566edd28e599b59a3be80405bedf150e5d5dd4d0f3d1d84e8e7f7dfe945d358493bb119470aabbf5b3" +
		"eb7205f2184793e5f9b41c0c622ebf0b83730feb3c2d06de8f7992cee469bf104595cd98307f7d3d584760b6f" +
		"1d75e10f51325626627050f5b636f34b93471c290b1afede150055b796d3d08f31b52360ef28630acc273bfcd" +
		"a6aa14df76867cc230c0597bd76105d7a54426698d87ad1ac683c7569b80f0f4c5d169dd0dbcf390e8449b698" +
		"649183cdf214a13e51ed5c5c38df9931ad23a05e49b85975bcc65cca5ebfb404f62552cf46fd535e5d9e8178df" +
		"f0156fbd6227e2e04c56af73e8a149dbd63f5cd0a5ec1046c30b3a25ba60cfc869df084553430e7058e948b8e4" +
		"26003421988789c266fcf9f6c309fcc785e11e76121316f82b61555352c91f3d936dbc1e181a6924d480ba09a6" +
		"2adf930dee5884ce5362ff31f1e2a4558702bc0d8c871cc322efad66efc946c3a9ae959ef20c052787d6a5e04d7" +
		"dc9dfc2c9941104ad26c136a9827a866b9e0942dbacd4aed56b48547c6dc1d0216fcdd2b5ce40828bdae5df48e" +
		"724232b01cc567173e07b9089e7834bb92c873c5e08ba055698df5f79ee73e122b5b72ee3e2e100858dad409da" +
		"55ad0fa1aa9caa60bf9c25e9ba3e1dc012724c89903a820b63dd5f14f0019007b180684afbe125a0cf87af796a" +
		"e20e465641c5e8fb91b6e7c6395d2f49f17bac3e35110c16b119bf289e11afb4bbae40266aa87605298ec5bb06" +
		"01fa415038621ea100db5d9d8a5da4d74fd92ed882546afc7a8a3dc648b1c7852e8fa43ca9ed287a4bb9dd299b" +
		"fc69414f990bf3b7b58a932a4ff9c86e2fb131b7cc7b65464cc80011267ab49f5c599b9ce43acc9a06b856b25b6" +
		"fe5f51afd6db147386a1ab30575a0eae607ffe116cae7fb70df6841ae0f52eaf359305becdf7f4636f3c31fab45" +
		"387ef97cef0b8ef6a8de702a2f1c21c3aee10382e8b8610a03bf6f1c54527a1d6db79f80f71c7f29880bb4b0d4" +
		"6cee3a6063028e901f2f3514639bce237259a3122beea38763e205263f663543bf9bb390337f6a992b74dbfab9" +
		"66a9abf3dd54b15956b47ee731d23ec9a87a0027ed16f6fc4384812df153231c61331ef22e16035719044fddd7" +
		"b6a9626aa8397073d0cbf42fffd2b8201dca65aadaf98048e7bc0917ed83c7cbb59086ceff885b523fca2d65d873" +
		"23fd6bbd75b0a312b317b217985334086a63cdc4f065be41dfc590c76d71f93f76c091ee6b2878c2d718adde44" +
		"93eef3a4cb8b2764e7013b80f922bf2b3b3572029975bc1388b7c975f353a02fa01ab679bbe041041dc1425787" +
		"606df44013b7627c4d43b1edbda3768386f2b9a78470ac7ac5ca6b2d20385d53e2e412828e2ebcdd17ce8658c6" +
		"55babeefe0b2f43f606a192613263a2c27831a7c5953c9a1f2910093b4720e78e3b34ae7102e1094fcc6655d3a" +
		"f6d9a4c8f58f2478ef532121b7c91fe558a80257d63d8e9b4300c09dc04d9d37975f5cf3e548f23e40c0708224" +
		"19a74267d08453815ba8e02943c3bc5a13ad669fd79d8e4ee5f5be82dc638ba9a1d"

	SKReaderZab = "6423502f843d8cda01fbd9fa46cb397534a740ab1ec3d1076fbcb12e1dca2589"
	SKReaderKey = "58d277d8719e62a1561d248f403f477e9e6c37bf5d5fc5126f8f4c727c22dfc9"
	SKDeviceZab = "6423502f843d8cda01fbd9fa46cb397534a740ab1ec3d1076fbcb12e1dca2589"
	SKDeviceKey = "81d170e07fbdac93c1a676242c2576124a380d87bb73ed9ce4834de2272cf409"

	SessionTranscriptHex = "d81859024183d8185858a20063312e30018201d818584ba4010220012158205a88" +
		"d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d" +
		"4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415" +
		"531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c3" +
		"39bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696" +
		"f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f7" +
		"2673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba401022" +
		"0012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858dd" +
		"c7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd9102254872159102026372010211020461" +
		"6301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e" +
		"626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d48" +
		"23a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e6" +
		"42e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc" +
		"35e700a6b020414"

	DeviceRequestHex = "a26776657273696f6e63312e306b646f63526571756573747381a26c6974656d7352657175657374d8185893" +
		"a267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573a171" +
		"6f72672e69736f2e31383031332e352e31a66b66616d696c795f6e616d65f56f646f63756d656e745f6e756d" +
		"626572f57264726976696e675f70726976696c65676573f56a69737375655f64617465f56b6578706972795f" +
		"64617465f568706f727472616974f46a726561646572417574688443a10126a118215901b7308201b3308201" +
		"58a00302010202147552715f6add323d4934a1ba175dc945755d8b50300a06082a8648ce3d0403023016311430" +
		"1206035504030c0b72656164657220726f6f74301e170d3230313030313030303030305a170d3233313233313" +
		"030303030305a3011310f300d06035504030c067265616465723059301306072a8648ce3d020106082a8648ce" +
		"3d03010703420004f8912ee0f912b6be683ba2fa0121b2630e601b2b628dff3b44f6394eaa9abdbcc2149d29d6f" +
		"f1a3e091135177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185301c0603551d1f04153013301" +
		"1a00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f30b464fada20bfcd533a" +
		"f5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e300e0603551d0f010" +
		"1ff04040302078030150603551d250101ff040b3009060728818c5d050106300a06082a8648ce3d040302034900" +
		"3046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec4aae4e307206f9214930221009b94f0d739" +
		"dfa84cca29efed529dd4838acfd8b6bee212dc6320c46feb839a35f658401f3400069063c189138bdcd2f6314" +
		"27c589424113fc9ec26cebcacacfcdb9695d28e99953becabc4e30ab4efacc839a81f9159933d192527ee91b44" +
		"9bb7f80bf"

	DeviceResponseHex = "a36776657273696f6e63312e3069646f63756d656e747381a367646f6354797065756f72672e69736f2e313" +
		"83031332e352e312e6d444c6c6973737565725369676e6564a26a6e616d65537061636573a1716f72672e69" +
		"736f2e31383031332e352e3186d8185863a4686469676573744944006672616e646f6d58208798645b20ea" +
		"200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e971656c656d656e744964656e74696669657" +
		"26b66616d696c795f6e616d656c656c656d656e7456616c756563446f65d818586ca468646967657374494" +
		"4036672616e646f6d5820b23f627e8999c706df0c0a4ed98ad74af988af619b4bb078b89058553f44615d7" +
		"1656c656d656e744964656e7469666965726a69737375655f646174656c656c656d656e7456616c7565d90" +
		"3ec6a323031392d31302d3230d818586da4686469676573744944046672616e646f6d5820c7ffa307e5de92" +
		"1e67ba5878094787e8807ac8e7b5b3932d2ce80f00f3e9abaf71656c656d656e744964656e746966696572" +
		"6b6578706972795f646174656c656c656d656e7456616c7565d903ec6a323032342d31302d3230d818586d" +
		"a4686469676573744944076672616e646f6d582026052a42e5880557a806c1459af3fb7eb505d378156632" +
		"9d0b604b845b5f9e6871656c656d656e744964656e7469666965726f646f63756d656e745f6e756d626572" +
		"6c656c656d656e7456616c756569313233343536373839d818590471a4686469676573744944086672616e" +
		"646f6d5820d094dad764a2eb9deb5210e9d899643efbd1d069cc311d3295516ca0b024412d71656c656d65" +
		"6e744964656e74696669657268706f7274726169746c656c656d656e7456616c7565590412ffd8ffe000104a" +
		"46494600010101009000900000ffdb004300130d0e110e0c13110f11151413171d301f1d1a1a1d3a2a2c233" +
		"0453d4947443d43414c566d5d4c51685241435f82606871757b7c7b4a5c869085778f6d787b76ffdb004301" +
		"1415151d191d381f1f38764f434f7676767676767676767676767676767676767676767676767676767676" +
		"767676767676767676767676767676767676767676ffc00011080018006403012200021101031101ffc4001" +
		"b00000301000301000000000000000000000005060401020307ffc400321000010303030205020309000000000" +
		"000010203040005110612211331141551617122410781a1163542527391b2c1f1ffc40015010101000000000" +
		"00000000000000000000001ffc4001a110101010003010000000000000000000000014111213161ffda000c03010" +
		"002110311003f00a5bbde22da2329c7d692bc7d0d03f52cfb0ff75e7a7ef3e7709723a1d0dae146ddfbb3c039ce" +
		"07ad2bd47a7e32dbb8dd1d52d6ef4b284f64a480067dfb51f87ffb95ff00eb9ff14d215de66af089ce44b7dbde9cb" +
		"6890a2838eddf18078f7add62d411ef4db9b10a65d6b95a147381ea0d495b933275fe6bba75c114104a8ba4104" +
		"13e983dff004f5af5d34b4b4cde632d0bf1fd1592bdd91c6411f3934c2fa6af6b54975d106dcf4a65ae56e85600" +
		"1ebc03c7ce29dd9eef1ef10fc447dc9da76ad2aee93537a1ba7e4f70dd8eff0057c6dffb5e1a19854a83758e5452" +
		"8750946ec6704850cd037bceb08b6d7d2cc76d3317fc7b5cc04fb6707269c5c6e0c5b60ae549242123b0e493f6" +
		"02a075559e359970d98db89525456b51c951c8afa13ea8e98e3c596836783d5c63f5a61a99fdb7290875db4be8" +
		"8ab384bbbbbfc7183fdeaa633e8951db7da396dc48524fb1a8bd611a5aa2a2432f30ab420a7a6d3240c718cf03" +
		"1fa9ef4c9ad550205aa02951df4a1d6c8421b015b769db8c9229837ea2be8b1b0d39d0eba9c51484efdb8c0efd" +
		"8d258daf3c449699f2edbd4584e7af9c64e3f96b9beb28d4ac40931e6478c8e76a24a825449501d867d2b1dcde" +
		"bae99b9c752ae4ecd6dde4a179c1c1e460938f9149ef655e515c03919a289cb3dca278fb7bf177f4faa829dd8c" +
		"e3f2ac9a7ecde490971fafd7dce15eed9b71c018c64fa514514b24e8e4f8c5c9b75c1e82579dc1233dfec08238" +
		"f6add62d391acc1c5256a79e706d52d431c7a0145140b9fd149eb3a60dc5e88cbbc2da092411e9dc71f39a7766" +
		"b447b344e847dcac9dcb5abba8d145061d43a6fcf1e65cf15d0e90231d3dd9cfe62995c6dcc5ca12a2c904a15f" +
		"71dd27d451453e09d1a21450961cbb3ea8a956433b781f1ce33dfed54f0e2b50a2b71d84ed6db18028a28175f7" +
		"4fc6bda105c529a791c25c4f3c7a11f71586268f4a66b726e33de9ea6f1b52b181c760724e47b514520a5a28a2" +
		"83ffd9d81858ffa4686469676573744944096672616e646f6d58204599f81beaa2b20bd0ffcc9aa03a6f985befab3" +
		"f6beaffa41e6354cdb2ab2ce471656c656d656e744964656e7469666965727264726976696e675f70726976696c" +
		"656765736c656c656d656e7456616c756582a37576656869636c655f63617465676f72795f636f646561416a69" +
		"737375655f64617465d903ec6a323031382d30382d30396b6578706972795f64617465d903ec6a323032342d31" +
		"302d3230a37576656869636c655f63617465676f72795f636f646561426a69737375655f64617465d903ec6a32" +
		"3031372d30322d32336b6578706972795f64617465d903ec6a323032342d31302d32306a697373756572417574" +
		"688443a10126a118215901f3308201ef30820195a00302010202143c4416eed784f3b413e48f56f075abfa6d87" +
		"eb84300a06082a8648ce3d04030230233114301206035504030c0b75746f7069612069616361310b3009060355" +
		"040613025553301e170d3230313030313030303030305a170d3231313030313030303030305a30213112301006" +
		"035504030c0975746f706961206473310b30090603550406130255533059301306072a8648ce3d020106082a86" +
		"48ce3d03010703420004ace7ab7340e5d9648c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d57d8" +
		"983e1b37d3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a5301e0603551d12041730" +
		"1581136578616d706c65406578616d706c652e636f6d301c0603551d1f041530133011a00fa00d820b6578616d" +
		"706c652e636f6d301d0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351301f0603551d230" +
		"4183016801454fa2383a04c28e0d930792261c80c4881d2c00b300e0603551d0f0101ff04040302078030150603" +
		"551d250101ff040b3009060728818c5d050102300a06082a8648ce3d040302034800304502210097717ab901674" +
		"0c8d7bcdaa494a62c053bbdecce1383c1aca72ad08dbc04cbb202203bad859c13a63c6d1ad67d814d43e2425ca" +
		"f90d422422c04a8ee0304c0d3a68d5903a2d81859039da66776657273696f6e63312e306f646967657374416c6" +
		"76f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e31383031332e352" +
		"e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf01582067e539d61" +
		"39ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5d869780e6" +
		"1eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e41ac52dac" +
		"9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac2d5905582" +
		"0fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae77db815de" +
		"4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857dd438d627c" +
		"f32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7312377e06" +
		"8f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c98a170cf3" +
		"6e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30faaaae6cc" +
		"d5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485146c67c74" +
		"ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c5640610ff1" +
		"a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24c8cd003ec" +
		"f94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98c2f544035" +
		"820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d6465766963654b6579496" +
		"e666fa1696465766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c75" +
		"3e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d6676" +
		"46f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa366736" +
		"9676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc074323032302d313" +
		"02d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a33303a303" +
		"25a584059e64205df1e2f708dd6db0847aed79fc7c0201d80fa55badcaf2e1bcf5902e1e5a62e4832044b890ad" +
		"85aa53f129134775d733754d7cb7a413766aeff13cb2e6c6465766963655369676e6564a26a6e616d6553706163" +
		"6573d81841a06a64657669636541757468a1696465766963654d61638443a10105a0f65820e99521a85ad7891b" +
		"806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d6673746174757300"
)

var EDeviceKeyPublic *cose.Key
var EReaderKeyPublic *cose.Key

var EDeviceKey *ecdh.PrivateKey
var EReaderKey *ecdh.PrivateKey

func init() {
	{
		x, err := hex.DecodeString(EDeviceKeyX)
		if err != nil {
			panic(err)
		}

		y, err := hex.DecodeString(EDeviceKeyY)
		if err != nil {
			panic(err)
		}

		d, err := hex.DecodeString(EDeviceKeyD)
		if err != nil {
			panic(err)
		}

		EDeviceKeyPublic, err = cose.NewKeyEC2(cose.AlgorithmES256, x, y, nil)
		if err != nil {
			panic(err)
		}

		EDeviceKey, err = ecdh.P256().NewPrivateKey(d)
		if err != nil {
			panic(err)
		}
	}

	{
		x, err := hex.DecodeString(EReaderKeyX)
		if err != nil {
			panic(err)
		}

		y, err := hex.DecodeString(EReaderKeyY)
		if err != nil {
			panic(err)
		}

		d, err := hex.DecodeString(EReaderKeyD)
		if err != nil {
			panic(err)
		}

		EReaderKeyPublic, err = cose.NewKeyEC2(cose.AlgorithmES256, x, y, nil)
		if err != nil {
			panic(err)
		}

		EReaderKey, err = ecdh.P256().NewPrivateKey(d)
		if err != nil {
			panic(err)
		}
	}
}

func TestDecodeDeviceEngagement(t *testing.T) {
	deviceEngagementBytes, err := hex.DecodeString(DeviceEngagementHex)
	if err != nil {
		t.Fatal(err)
	}

	var deviceEngagement DeviceEngagement
	if err = cbor.Unmarshal(deviceEngagementBytes, &deviceEngagement); err != nil {
		t.Fatal(err)
	}

	eDeviceKey, err := deviceEngagement.EDeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		EDeviceKeyPublic,
		eDeviceKey,
		cmp.FilterPath(
			func(p cmp.Path) bool {
				return p.String() == "Algorithm"
			},
			cmp.Ignore(),
		),
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestDecodeSessionEstablishment(t *testing.T) {
	sessionEstablishmentBytes, err := hex.DecodeString(SessionEstablishmentHex)
	if err != nil {
		t.Fatal(err)
	}

	var sessionEstablishment SessionEstablishment
	if err = cbor.Unmarshal(sessionEstablishmentBytes, &sessionEstablishment); err != nil {
		t.Fatal(err)
	}

	eReaderKey, err := sessionEstablishment.EReaderKey()
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		EReaderKeyPublic,
		eReaderKey,
		cmp.FilterPath(
			func(p cmp.Path) bool {
				return p.String() == "Algorithm"
			},
			cmp.Ignore(),
		),
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestDecodeSessionData(t *testing.T) {
	sessionDataBytes, err := hex.DecodeString(SessionDataHex)
	if err != nil {
		t.Fatal(err)
	}

	var sessionData SessionData
	if err = cbor.Unmarshal(sessionDataBytes, &sessionData); err != nil {
		t.Fatal(err)
	}
}

func TestReaderSessionEncryption(t *testing.T) {
	sessionTranscriptBytes, err := hex.DecodeString(SessionTranscriptHex)
	if err != nil {
		t.Fatal(err)
	}

	eDeviceKey, err := NewECDHPublicKeyFromCOSEKey(*EDeviceKeyPublic)
	if err != nil {
		t.Fatal(err)
	}

	skReader, err := SKReader(EReaderKey, eDeviceKey, sessionTranscriptBytes)
	if err != nil {
		t.Fatal(err)
	}

	skReaderExpected, err := hex.DecodeString(SKReaderKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skReaderExpected, skReader) {
		t.Fatal()
	}

	skDevice, err := SKDevice(EReaderKey, eDeviceKey, sessionTranscriptBytes)
	if err != nil {
		t.Fatal(err)
	}

	skDeviceExpected, err := hex.DecodeString(SKDeviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skDeviceExpected, skDevice) {
		t.Fatal()
	}

	_, err = NewReaderSessionEncryption(skReader, skDevice)
}

func TestDecodeDeviceRequest(t *testing.T) {
	deviceRequestBytes, err := hex.DecodeString(DeviceRequestHex)
	if err != nil {
		t.Fatal(err)
	}

	var deviceRequest DeviceRequest
	err = cbor.Unmarshal(deviceRequestBytes, &deviceRequest)
	if err != nil {
		t.Fatal(err)
	}

	for _, docRequest := range deviceRequest.DocRequests {
		_, err := docRequest.ItemsRequest()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDecodeDeviceResponse(t *testing.T) {
	deviceResponseBytes, err := hex.DecodeString(DeviceResponseHex)
	if err != nil {
		t.Fatal(err)
	}

	var deviceResponse DeviceResponse
	err = cbor.Unmarshal(deviceResponseBytes, &deviceResponse)
	if err != nil {
		t.Fatal(err)
	}

	for _, document := range deviceResponse.Documents {
		_, err := document.IssuerSigned.NameSpaces.IssuerSignedItems()
		if err != nil {
			t.Fatal(err)
		}

		_, err = document.IssuerSigned.IssuerAuth.MobileSecurityObject()
		if err != nil {
			t.Fatal(err)
		}

		_, err = document.DeviceSigned.NameSpaces()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDecodeSessionTranscript(t *testing.T) {
	sessionTranscriptTagged, err := hex.DecodeString(SessionTranscriptHex)
	if err != nil {
		t.Fatal(err)
	}

	var sessionTranscriptBytes TaggedEncodedCBOR
	err = cbor.Unmarshal(sessionTranscriptTagged, &sessionTranscriptBytes)
	if err != nil {
		t.Fatal(err)
	}

	sessionTranscriptBytesUntagged, err := sessionTranscriptBytes.UntaggedValue()
	if err != nil {
		t.Fatal(err)
	}

	var sessionTranscript SessionTranscript
	err = cbor.Unmarshal(sessionTranscriptBytesUntagged, &sessionTranscript)
	if err != nil {
		t.Fatal(err)
	}
}
