Praktični rad - Seafile
=======================

**Autori:** *Dominik Rusac, Berneš Stefano*

-------------------------------------------

U ovoj dokumentaciji bit će prikazan postupak instalacije i postavljanja:

- web poslužitelja Nginx
- samopotpisani SSL certifikat
- sustav za upravljanje bazama podataka MySQL
- Memcached
- Seafile

Korišten je operativni sustav Ubuntu 18.10 x64 na mašini sa 4 GB memorije i 80 GB hard diska.

1.1. Prvi korak je `instalirati i postaviti nginx server <https://www.digitalocean.com/community/tutorials/how-to-install-nginx-on-ubuntu-18-04>`_
na sljedeći način:

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

S obzirom da je ovo prvi dodir sa ``apt`` sustavom pakiranja, potrebno je sve ažurirati lokalne indeks paketekako bi imali pristup najnovijim popisom paketa. Nakon toga instaliramo nginx:

::

    sudo apt status
    sudo apt version
    sudo apt update
    sudo apt install nginx

Nakon prihvaćanja procedure, ``apt`` instalira Nginx i sve popratne datoteke na server. 

1.2. Drugi korak je postavljanje vatrozida.

Prije testiranja Nginx-a, softver vatrozida mora se postaviti za dopuštanje pristupa servisu. Nginx registrira sam sebe kao servis sa naredbom ``ufw`` prilikom instalacije, čineći pristup Nginx-u vrlo jednostavnim.

Stvara se popis aplikacijskih konfiguracija koristeći ``ufw`` kako bi se znalo s kojim aplikacijama raditi:

::

	sudo ufw app list

Izlaz treba izgledati kao u nastavku:
::

	Available applications:
	 Nginx Full
	 Nginx HTTP
	 Nginx HTTPS
	 OpenSSH

Postoje tri dostupna profila za Nginx:

* **Nginx Full**: Taj profil otvara port 80 (normalan, nekriptirani promet)i port 443 (TLS/SSL kriptirani promet)
* **Nginx HTTP**: Taj profil otvara samo port 80 
* **Nginxx HTTPS**: Taj profil otvara samo port 443

Preporučljivo je omogućiti najrestriktivniji profil koji će i dalje omogućiti konfigurirani promet. Budući da još nije konfiguriran SSL za naš poslužitelj, treba samo dopustiti promet na portu 80.

To se uključue na sljedeći način:

::

	sudo ufw allow 'Nginx HTTP'

Promjenu se može provjeriti utipkavanjem:

::

	sudo ufw status

Sad bi se trebao vidjeti HTTP promet u izlaznom prikazu:

::

	Status: active

	To                         Action      From
	--                         ------      ----
	OpenSSH                    ALLOW       Anywhere                  
	Nginx HTTP                 ALLOW       Anywhere                  
	OpenSSH (v6)               ALLOW       Anywhere (v6)             
	Nginx HTTP (v6)            ALLOW       Anywhere (v6)


1.3. Treći korak je provjera web servera.

Na kraju instalacijskog procesa, Ubuntu 18.10 pokreće Nginx. Web server bi trebao biti objavljen i pokrenut, a to možemo provjeriti utipkavanjem naredbe ``systemd``.

::

	systemctl status nginx

::

	nginx.service - A high performance web server and a reverse proxy server
   Loaded: loaded (/lib/systemd/system/nginx.service; enabled; vendor preset: enabled)
   Active: active (running) since Fri 2018-04-20 16:08:19 UTC; 3 days ago
     Docs: man:nginx(8)
 Main PID: 2369 (nginx)
    Tasks: 2 (limit: 1153)
   CGroup: /system.slice/nginx.service
           ├─2369 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
           └─2380 nginx: worker process

Kao što je vidljivo iznad, servis izgleda uspješno pokrenut. Međutim, najbolji način za testiranje je pokretanje stranice od Nginx-a. 
Pristupati se može zadanoj Nginx stranici kako bi se provjerilo da je softver pokrenut, dovoljno je upisati serverovu IP adresu. 
IP adresa se saznaje da nekoliko načina:

::

	 ip addr show eth0 | grep inet | awk '{ print $2; }' | sed 's/\/.*$//'

Natrag se dobije nekoliko linija koda. Alternativan način za dobivanje javne IP adrese vidljive svima na internetu je sljedeći:

::

	curl -4 icanhazip.com

Nakon dobivanja serverove IP adrese, nju se unosi u adresnu traku zadanog preglednika:

::

	http://your_server_ip

Prikazana bi trebala biti Nginx-ova početna stranica koja je uključena s Nginx-om za prikaz kako bi se lakše znalo ako je servis pokrenut ispravno.


1.4. Četvrti korak je upravljanje Nginx procesima.

Nakon što je web server pokrenut, može se isprobati nekoliko osnovnih komandi za upravljanje.

Za zaustavljanje web servera:

::

	sudo systemctl stop nginx

Za pokretanje web servera:

::
	
	sudo systemctl start nginx

Za zaustavljanje i onda odmah pokretanje servisa:

::

	sudo systemctl restart nginx

Ako se radi samo konfiguracijske postavke, Nginx može često učitavati bez prekida veze. To se radi na sljedeći način:

::

	sudo systemctl reload nginx

Nginx je zadan da se pokrene automatski kad se server pokrene. Ako se ne želi takav način pokretanja, to se može isključiti na sljedeći način:

::

	sudo systemctl disable nginx

Za ponovno aktiviranje servisa:

::

	sudo systemctl enable nginx


1.5. Peti korak je postavljanje Server blokova (preporučljivo).

Kada se koristi Nginx web poslužitelj, server blokovi (slično virtualnim hostovima u Apacheu) mogu se koristiti za enkapsuliranje konfiguracijskih detalja i hostanje više od jedne domene s jednog poslužitelja. Postavlja se domena pod nazivom seaFile.

Nginx na Ubuntu 18.04 ima jedan server blok kao zadani koji je konfiguriran za posluživanje dokumenata iz direktorija na ``/var/www/html``. Iako to dobro funkcionira za jednu web-lokaciju, može postati nezgrapno ako se radi hosting za više web-lokacija. Umjesto modificiranja ``/var/www/html``. Stavra se struktura direktorija unutar /var/www za našu web-lokaciju seaFile, ostavljajući ``/var/www/html`` kao zamjenski direktorij za posluživanje ako zahtjevi klijenta ne odgovaraju drugim web-stranicama. 
Stvara se direktorij za seafile koristeći ``-p`` kako bi se stvorio roditeljski direktorij:

::
	
	sudo mkdir -p /var/www/seaFile/html

Slijedi, dodati vlasništvo direktorija sa ``$USER`` varijablom:

::
	
	sudo chown -R $USER:$USER /var/www/seaFile/html

Dozvole za korijen web stranice trebale bi biti točne ako se nije mijenjalo ``umask`` vrijednost. Provjeriti se može da sljedeći način:

::
	
	sudo chmod -R 755 /var/www/seaFile

U nastavku je potrebno izraditi jednostavnu ``index.html`` stranicu koristeći ``nano`` ili neki drugi uređivač teksta:

::

	nano /var/www/seaFile/html/index.html


Unutra se dodaje sljedeći HTML kod:

::

	<html>
		<head>
			<title>Welcome to Example.com!</title>
		</head>
		<body>
			<h1>Success!  The example.com server block is working!<h1>
		</body>
	</html>

Pri završetku, datoteka se sprema i zatvara. 
Kako bi Nginx servirao sadržaj potrebno je stvoriti server blok sa točnim direktivama. Umjesto da se mijenja zadana konfiguracijska datoteka, stvara se nova na ``/etc/nginx/sites-available/seafile``:

::

	sudo nano /etc/nginx/sites-available/seafile

U konfiguracijski blok je potrebno zalijepiti slijedeći kod, sličan kao onaj zadani ali ažuriran na novi direktorij i novu domenu:

::

	server {
        listen 80;
        listen [::]:80;

        root /var/www/seaFile/html;
        index index.html index.htm index.nginx-debian.html;

        server_name stuffer.xyz www.stuffer.xyz;

        location / {
                try_files $uri $uri/ =404;
        }
    }	

Ažurirana je ``root`` konfiguracija na nov direktorij i ``server_name`` na novu domenu.
Slijedi, omogućavanje datoteke stvaranjem linka od nje do ``sites-enabled`` direktorija kojeg Nginx čita prilikom pokretanja:

::

	sudo ln -s /etc/nginx/sites-available/seafile /etc/nginx/sites-enabled/

Dva server bloka su sad omogućena i konfigurirana kako bi se javljala na zahtjeve svojih ``listen`` i ``server_name`` direktivama.

Kako bi se izbjegli problemi s hash memorijom koji se mogu prouzrokavati dodavanjem novih server imena, potrebno je namjestiti vrijednosti u ``/etc/nginxnginx.conf`` datoteci:

::

	sudo nano /etc/nginx/nginx.conf

Traži se ``server_names_bucket_size`` direktiva i uklanja se ``#`` simbol za otkomentiranje linije:

::

		...
	http {
	    ...
	    server_names_hash_bucket_size 64;
	    ...
	}
	...

Sljedeće, kako bi se provjerilo da nema grešaka u sintaksi u Nginx datotekama:

::
	
	sudo nginx -t

Datoteka se sprema i zatvara.
Ako nema nikakvih problema, Nginx je potrebno restartati kako bi se prihvatile promjene:

::

	sudo systemctl restart nginx

Nginx bi sad trebao servirati željeno ime domene. Testiranje se provodi navigacijom do http://stuffer.xyz gdje je prikazan sadržaj index.htmla.

2. Web server je instaliran i sad slijedi `nabava i instalacija SSL certifikata <https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-18-04>`_.

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


Za dobavljanje SSL certifikata koristi se Let's Encrypt Certificate Authority (CA) koji pruža jednostavan način za dobivanje i instaliranje besplatnih `TLS/SSL certifikata <https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs>`_, čime se omogućuje šifrirani HTTPS na web poslužiteljima. Pojednostavljuje proces pružanjem klijentskog softvera Certbot koji pokušava automatizirati većinu (ako ne i sve) potrebne koraka. Trenutno je cijeli proces dobivanja i instaliranja certifikata potpuno automatiziran na Apache i Nginx.

U nastavku se koristi Certbot za dobivanje besplatnog SSL certifikata za Nginx na Ubuntu 18.04 i postavljanje automatskog obnavljanja certifikata.

Koristi se zasebna datoteka server bloka Nginx umjesto zadane datoteke. Preporuka je stvaranje novih Nginx server blok datoteka za svaku domenu jer pomaže u izbjegavanju uobičajenih pogrešaka i održava zadane datoteke kao zamjensku konfiguraciju.


2.1. Prvi korak je instalacija Certbot-a

Najprije treba instalirati Certbot softver na SSL server. Certbot je veoma često ažuriran pa je moguće da su paketi u Ubuntu zastarjeli. Međutim, razvijači Certbota održavaju Ubuntu repozitorij softvera u korak s trenutnim verzijama pa će se taj repozitorij koristiti u nastavku.

Dodaje se repozitorij:

::
	
	sudo add-apt-repository ppa:certbot/certbot

Potrebno je pritisnuti `ENTER` za potvrdu.
Nakon toga je potrebno instalirati Certbot Nginx paket pomoću `apt`:

::

	sudo apt install python-certbot-nginx

Sad je Certbot spreman za korištenje ali kako bi konfigurirao SSL za Nginx, mora se provjeriti neka Nginx konfiguracija.


2.2. Drugi korak je potvrda Nginx konfiguracije

Certbot mora znat odabrat točni `server` blok u Nginx konfiguraciji kako bi automatski konfigurirao SSL. Posebno se to radi traženjem `serve_name` direktive koji odgovara domeni za koju se zahtjevao certifikat. 
Ukoliko je do sad sve dobro napravljeno, trebalo bi imati server blok za domenu u /etc/nginx/sites-available/seafile sa direktivom `server_name` već točno postavljenom. 

Za provjeru, otvara se datoteka server bloka za zadanu domenu koristeći `nano` ili neki drugi uređivač teksta:

::

	sudo nano /etc/nginx/sites-available/example.com

Postojeća `servern_name` linija bi trebalo izgledati nešto kao u nastavku:

::

	...
		server_name example.com www.example.com;
	...

Ako postoji, izlazi se iz uređivača i prelazi na sljedeći korak.
Ako ne postoji, tada se treba ažurirati da paše. Sprema se, izlazi iz uređivača i provjerava sintaksa konfiguracijskih izmjena:

::

	sudo nginx -t

Ako dolazi do greške, ponovno otvoriti datoteku server bloka i provjeriti ako je nešto krivo napisano ili ako fali nekakav znak. Jednom kad je sintaksa u konfiguracijskoj datoteci točna, Nginx treba resetirat za učitavanjem nove konfiguracije:

::

	sudo systemctl reload nginx

Certbot sada može naći točan `server` blok i ažurirati ga.

2.3. Treći korak je dopuštanje HTTPS-a kroz vatrozid

Ako je `ufw` vatrozid uključen potrebno je podesiti postavke za propuštanje HTTPS prometa. Srećom, Nginx registrira nekoliko `ufw` profila prilikom instalacije.

Trenutne postavke se provjeravaju na sljedeći način:

::

	sudo ufw status

Najvjerojatnije izgleda kao u nastavku, što znači da je samo HTTP promet dopušten na web serveru:

::

	Output
	Status: active

	To                         Action      From
	--                         ------      ----
	OpenSSH                    ALLOW       Anywhere                  
	Nginx HTTP                 ALLOW       Anywhere                  
	OpenSSH (v6)               ALLOW       Anywhere (v6)             
	Nginx HTTP (v6)            ALLOW       Anywhere (v6)

Za dodatno puštanje HTTPS prometa, dopušta se Nginx Full Profil i briše se dozvola za Nginx HTTP profil:

::

	sudo ufw allow 'Nginx Full'
	sudo ufw delete allow 'Nginx HTTP'

Status bi sad trebao izgledati ovako:

::

	sudo ufw status

::

	Output
	Status: active

	To                         Action      From
	--                         ------      ----
	OpenSSH                    ALLOW       Anywhere
	Nginx Full                 ALLOW       Anywhere
	OpenSSH (v6)               ALLOW       Anywhere (v6)
	Nginx Full (v6)            ALLOW       Anywhere (v6)


2.4. Četvrti korak je nabava SSL Certifikata.

Certbot pruža nekoliko načina nabava SSL certifikata kroz dodatke ( *plugin*). Nginx plugin će se pobrinuti za ponovnu konfiguraciju i osvježenje konfiguracije kada je to potrebno. Za upotrebu plugin-a je potrebno utipkati slijedeće:

::

	 sudo certbot --nginx -d example.com -d www.example.com

To pokreće `certbot` sa `--nginx` pluginom, koristeći `-d` za specifikaciju imena za koja se želi da certifikat vrijedi.

Ako se `certbot` koristi po prvi put, sustav će upitati za email adresu i prihvaćanje uvjeta korištenja. Nakon toga, `certbot` komunicira sa Let's Encrypt serverom i pokreće verifikaciju da smo mi zapravo vlasnici domene za koju se zahtjeva certifikat.
Ako je to uspješno, `certbot` će upitati kako se žele namjestiti HTTPS postavke.

::

	Output
	Please choose whether or not to redirect HTTP traffic to HTTPS, removing HTTP access.
	-------------------------------------------------------------------------------
	1: No redirect - Make no further changes to the webserver configuration.
	2: Redirect - Make all requests redirect to secure HTTPS access. Choose this for
	new sites, or if you're confident your site works on HTTPS. You can undo this
	change by editing your web server's configuration.
	-------------------------------------------------------------------------------
	Select the appropriate number [1-2] then [enter] (press 'c' to cancel):

Nakon željenog odabira valjda pritisnuti `ENTER`. Konfiguracija se ažurira i Nginx se ponovno pokreće za pokupljanje novih postavki. `certbot` će ispisati završnu poruku kako je proces uspješno dovršen i mjesto gdje je certifikat spremljen:

::

	IMPORTANT NOTES:
	 - Congratulations! Your certificate and chain have been saved at:
	   /etc/letsencrypt/live/stuffer.xyz/fullchain.pem
	   Your key file has been saved at:
	   /etc/letsencrypt/live/stuffer.xyz/privkey.pem
	   Your cert will expire on 2019-04-29. To obtain a new or tweaked
	   version of this certificate in the future, simply run certbot again
	   with the "certonly" option. To non-interactively renew *all* of
	   your certificates, run "certbot renew"
	 - Your account credentials have been saved in your Certbot
	   configuration directory at /etc/letsencrypt. You should make a
	   secure backup of this folder now. This configuration directory will
	   also contain certificates and private keys obtained by Certbot so
	   making regular backups of this folder is ideal.
	 - If you like Certbot, please consider supporting our work by:

	   Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate
	   Donating to EFF:                    https://eff.org/donate-le

Certifikati su sad preuzeti, instalirani i učitani. Osvježavanjem web stranice koristeći `https:/` primjećuje se sigurnosni indikator u web pregledniku. To ukazuje da je web stranica pravlno zaštićena, inače sa zelenim lokotom. Ako se testira server koristeći `SSL Labs Server Test <https://www.ssllabs.com/ssltest/>`_ ono će dobiti A ocjenu.

2.5. Peti korak je verifikacija Certbot Automatske obnove

Let's Encrypt certifikati su važeći samo 90 dana. To je zato da potakne korisnike za automatizacijom procesa obnove certifikata. `certbot` paket koji je instaliran se brine o tome umjesto nas tako što dodaje skriptu za obnovu u `/etc/cron.d`. Skripta se pokrene dva puta na dan i automatski obnavlja svaki certifikat koji ističe za 30 dana.

Za testiranje procesa obnove, može se obaviti testno pokretanje sa `certbot-om`:

::

	sudo certbot renew --dry-run

Ako nema grešaka, tada je sve u redu. Kada je potrebno, Certbot će obnoviti certifikate i ponovno pokrenuti Nginx da se primjene izmjene. Ako proces bilo kad zapne, Let's Encrypt šalje poruku na željenu email adresu s upozoranjem da certifikat brzo ističe.


3. SSL certifikat je valjan i sad slijedi `instalacija MySQL baze podataka <https://www.digitalocean.com/community/tutorials/how-to-install-linux-nginx-mysql-php-lemp-stack-ubuntu-18-04>`_ 

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

MySQL je program iz skupine LEMP alata koji se koriste za dinamičke web stranice i web aplikacije. LEMP je akronim koji opisuje Linux operativne sustave sa Nginx web serverom (Engine-x je izgovor). Pozadinski podaci su spremljeni u MySQL bazi podataka i dinamično se procesiraju sa PHP-om. 

U našem slučaju nije potreban cijeli LEMP paket nego samo MySQL (Sustav za upravljanje bazama podataka) s kojim će se spremati i upravljati podaci na web stranici.

MySQL se instalira na sljedeći način:

::

	sudo apt install mysql-server

MySQL baza podataka je sad instalirana ali konfiguracija još nije dovršena. Kako bi instalacija bila sigurna, MySQL dolazi sa skriptom koja će upitati žele li se mijenjati delikatni zadani podaci. Skripta se inicira na način:

::

	sudo mysql_secure_installation

Skripta će pitati ako se želi konfigurirati `VALIDATE PASSWORD PLUGIN`.

**Upozorenje**: uključivanje ove značajke je stvar pojedinca. Ako se uključi, lozinke koje ne štimaju sa specifičnim kriterijima bit će izbačene od strane MySQL-a sa greškom. To stvara probleme ako se koristi slaba lozinka u sprezi sa softverom koji automatski konfigurira korisničke podatke MySQL-a, kao što je Ubuntu paket phpMyAdmin. Sigurno je ostaviti validaciju isključenu ali mora se uvijek koristiti jake, jedinstvene lozinke za podatke baze.

Odgovara se sa `Y` za da ili bilo što drugo ako se želi nastaviti bez uključivanja.

::

		VALIDATE PASSWORD PLUGIN can be used to test passwords
	and improve security. It checks the strength of password
	and allows the users to set only those passwords which are
	secure enough. Would you like to setup VALIDATE PASSWORD plugin?

	Press y|Y for Yes, any other key for No:

Ako je odabrana validacija, skripta će također upitati da se unese određena razina validacije lozinke. Treba uzeti u obzir, ako se odabere **2** - za najjaču razinu - dolaziti će greške prilikom postavljanja lozinke koja ne sadrži brojeve, velika slova, mala slova i posebne znakove ili koje su osnovane na općim riječima z rječnika.

::

	There are three levels of password validation policy:

	LOW    Length >= 8
	MEDIUM Length >= 8, numeric, mixed case, and special characters
	STRONG Length >= 8, numeric, mixed case, special characters and dictionary                  file

	Please enter 0 = LOW, 1 = MEDIUM and 2 = STRONG: 1

U nastavku se postavlja upit za postavljanjem i potvrdom korjenske lozinke:

::

	Please set the password for root here.

	New password: 

	Re-enter new password: 

Za ostatak pitanja, poželjno je upisati `Y` i pritisnuti `ENTER` na svakom upitu. To će ukloniti neke anonimne korisnike i testirati bazu podataka, onemogućiiti korjensku prijavu s udaljenog računala i učitati nova pravila kako bi MySQL odmah prihvatio napravljene promjene. 

Ubuntu sustavi koji koriste MySQL 5.7 (ili kasnije verzije), korjenski MySQL korisnik je postavljen da verificira `auth_socket` plugin po zadanim postavkama, radije nego sa lozinkom. To omogućava veću sigurnost i iskoristivost u većini slučajeva, ali može i zakomplicirati stvari kad treba dati pristup vanjskom programu (npr. phpMyAdmin).

Ako se koristi `auth_socket` plugin za pristup MySQL-u može se nastaviti na slijedeći korak. Međutim ako se želi koristiti lozinka prilikom povezivanja na MySQL kao **root**, treba se promijeniti verifikacijska metoda sa `auth_socket` u `mysql_native_password`. Za to napraviti, potrebno je otvoriti MySQL prozor iz terminala:

::

	sudo mysql

Provjeriti koju autentifikacijsku metodu koriste MySQL korisnici sljedećom naredbom:

::

	mysql> SELECT user,authentication_string,plugin,host FROM mysql.user;

::

	Output
	+------------------+-------------------------------------------+-----------------------+-----------+
	| user             | authentication_string                     | plugin                | host      |
	+------------------+-------------------------------------------+-----------------------+-----------+
	| root             |                                           | auth_socket           | localhost |
	| mysql.session    | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE | mysql_native_password | localhost |
	| mysql.sys        | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE | mysql_native_password | localhost |
	| debian-sys-maint | *CC744277A401A7D25BE1CA89AFF17BF607F876FF | mysql_native_password | localhost |
	+------------------+-------------------------------------------+-----------------------+-----------+
	4 rows in set (0.00 sec)

U ovom primjeru je vidljivo kako root ima autentifikaciju putem `auth_socket` plugina. Za konfiguraciju root računa sa autentifikacijom sa lozinkom, pokreće se `ALTER USER` naredba. Potrebno je promijeniti `password` po želji:

::

	 mysql> ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';

Nakon toga se pokrene `FLUSH PRIVILEGES` koji govore serveru da ponovno pokrene tablice i prihvati napravljene promjene.

::

	mysql> FLUSH PRIVILEGES;

Opet provjeriti autentifikacijske metode svakog korisnika kako bi se utvrdilo da root više ne koristi autentifikaciju putem `auth_socket` plugina:

::

	mysql> SELECT user,authentication_string,plugin,host FROM mysql.user;

::

		Output
	+------------------+-------------------------------------------+-----------------------+-----------+
	| user             | authentication_string                     | plugin                | host      |
	+------------------+-------------------------------------------+-----------------------+-----------+
	| root             | *3636DACC8616D997782ADD0839F92C1571D6D78F | mysql_native_password | localhost |
	| mysql.session    | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE | mysql_native_password | localhost |
	| mysql.sys        | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE | mysql_native_password | localhost |
	| debian-sys-maint | *CC744277A401A7D25BE1CA89AFF17BF607F876FF | mysql_native_password | localhost |
	+------------------+-------------------------------------------+-----------------------+-----------+
	4 rows in set (0.00 sec)

U ovom izlazu je vidljivo da MySQL root korisnik sad ima autentifikaciju putem lozinke. Jednom kad se to potvrdi na vlastitom serveru, može se izaći iz MySQL ljuske:

::

	mysql> exit

**Napomena**: Nakon konfiguracije MySQL root korisnika za autentifikaciju putem lozinke, više ne postoji mogućnost pristupanja MySQL-u sa `sudo mysql` naredbom kao prije. Umjesto toga se koristi:

::

	mysql -u root -p

Nakon unosa novo postavljene lozinke, pojavit će se MySQL prompt.


4. Sljedeća na redu je instalacija `SeaFile-a <https://www.howtoforge.com/tutorial/seafile-on-ubuntu-with-nginx/>`_.

---------------------------------------------------------------------------------------------------------------------

4.1. Prvi korak prije instalacije je provjera za ažuriranjima s obzirom da je Seafile aplikacija bazirana na Python-u. 
Ažuriramo Ubuntu repozitorij:

::

	sudo apt update

Nakon toga slijedi instalacija Python-a 2.7 sa svim pripadajućim datotekama:

::

	sudo apt install python -y
	sudo apt install python2.7 libpython2.7 python-setuptools python-pil python-ldap python-urllib3 ffmpeg python-pip python-mysqldb python-memcache python-requests -y


4.2. Drugi korak je postavljanje MySql-a

S obzirom da je gore već opisana instalacija MySQL-a sad će biti prikazani samo neki dijelovi koji prije nisu bili napisani i unosi prilikom stvaranja korisnika. Konfigurira se MySQL root lozinka `mysql_secure_installation`. Nakon toga se odabire srednja težina lozinke MEDIUM i broj 1, klikne se `ENTER` i utipka lozinka.

Slijedi kreiranje nove baze podataka za Seafile server. Izradit će se tri baze podataka za svaku Seafile komponentu i stvoriti novi korisnik. 

::

	mysql -u root -p

Sad se stvaraju tri nove baze podataka 'ccnet-db', 'seafile-db', 'seahub-db' i izradđuje korisnik 'dofano'. Prikaz u nastavku:

::

	create database `ccnet-db` character set = 'utf8';
	create database `seafile-db` character set = 'utf8';
	create database `seahub-db` character set = 'utf8';

	create user 'dofano'@'localhost' identified by 'd0f4nO!"#';

	GRANT ALL PRIVILEGES ON `ccnet-db`.* to `dofano`@localhost;
	GRANT ALL PRIVILEGES ON `seafile-db`.* to `dofano`@localhost;
	GRANT ALL PRIVILEGES ON `seahub-db`.* to `dofano`@localhost;

Sad je sve spremno i postavljeno.


4.3. Treći korak je preuzimanje Seafile servera za Linux sustav


Seafile server će raditi kao servis na systemd sustavu i biti pokrenut kao ne-korjenski korisnik.
Stvaramo novog korisnika 'dofano'.

::

	useradd -m -s /bin/bash dofano

Nakon toga se potrebno logirati kao korisnik 'dofano' i preuzeti seafile server pomoću `wget`.

::


	su - dofano
	wget https://download.seadrive.org/seafile-server_6.3.4_x86-64.tar.gz

Raspakira se 'seafile-server.tar.gz' datoteka i preimenuje u master direktorij kao 'seafile-server'.

::

	tar -xf seafile-server_6.2.5_x86-64.tar.gz
	mv seafile-server-6.2.5/ seafile-server/

Seafile Server izvorni kod će se preuzeti u `/home/dofano/seafile-server` direktorij.


4.4. Četvrti korak je instalacija Seafile Servera sa MySQL-om

Sada je potrebno instalirati Seafile Server koristeći MySQL skriptu za instalaciju osigurane od strane Seafile-a.

Sad se prijavljujemo kao korisnik 'dofano' i krenemo u `seafile-server` direktorij.

::

	su - dofano
	cd seafile-server/

Pokreće se `setup-seafile-mysql.sh` skripta.

::

	./setup-seafile-mysql.sh

Instalacijska skripta pokreće Python modul provjeru. Treba se provjeriti da su sve pripadajuće datoteke instalirane i tada se klikne `ENTER`.

Nakon toga se nalazimo u Seafile konfiguraciji i ispunjavamo redom:

* server name: upiše se željeni naziv servera
* server domain name: upiše se željeno ime domene
* seafile data directory: ostavlja se onako kako je zadano i pritisne Enter
* seafile fileserver port: ostavlja se na zadanom portu

Trebalo bi izgledati nešto slično kao u nastavku:

::

	---------------------------------
	This is your configuration
	---------------------------------

	    server name:            StufferCloud
	    server ip/domain:       www.stuffer.xyz

	    seafile data dir:       /home/dofano/seafile-data
	    fileserver port:        8082

	    database:               use existing
	    ccnet database:         ccnet-db
	    seafile database:       seafile-db
	    seahub database:        seahub-db
	    database user:          dofano

Poslije toga znamo da je instalacija i konfiguracija bila uspješna. Seafile fileserver radi pod portom 8082, a seahub servis radi pod portom 8000. 

U nastavku testiramo pokretanje seafile servera i seahub servera pomoću start skripte. 

Kao korisnik 'dofano', odlazimo do `~seafile-server-latest` direktorij.

::

	su - dofano
	cd ~/seafile-server-latest/

Pokreće se seafile server upisivanjem sljedeće naredbe:

::
	
	./seafile.sh start

Tada, pokreće se seahub server.

::

	./seahub.sh start

Prilikom prvog pokretanja `seahub.sh` start skripte, pojavljuje se upit za izradu admin korisnika i lozinke za seafile server. 
Upisuje se email admina i onda lozinka, pa klik na `Enter`.

Stvoreni su dakle admin korisnik i lozinka. Provjerava se seafile i seahub servisni portovi '8082' i '8080' koristeći slijedeću naredbu:

::

	netstat -plntu

Vidljiv je seafile server i seahub server kako su uspješno pokrenuti na Ubuntu operativnom sustavu. 

Sada zaustavljamo seafile i seahub servere.

::

	./seafile.sh stop
	./seahub.sh stop


4.5. Peti korak je konfiguracija Nginxa kao obrnutog Proxy Seafile servera


Za početak treba otputovati do `/etc/nginx` konfiguracijskog direktorija i kreirati novi virtualnu host datoteku 'seafile' koristeći nano ili neki drugi uređivač teksta.

::

	cd /etc/nginx/
	nano sites-available/seafile


U datoteci se mora nalaziti slijedeći saržaj:

::

	server {
	    listen       80;
	    server_name  stuffed.xyz;
	    rewrite ^ https://$http_host$request_uri? permanent;
	    server_tokens off;
	}

	server {
	    listen 443 ssl http2;
	    server_name stuffed.xyz;

	    ssl_certificate /etc/letsencrypt/live/stuffer.xyz/fullchain.pem;
	    ssl_certificate_key /etc/letsencrypt/live/stuffer.xyz/privkey.pem;
	    ssl_session_timeout 5m;
	    ssl_session_cache shared:SSL:5m;

	    ssl_dhparam /etc/nginx/dhparam.pem;

	    #SSL Security
	    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
	    ssl_ecdh_curve secp384r1;
	    ssl_prefer_server_ciphers on;
	    server_tokens off;
	    ssl_session_tickets off;

	    proxy_set_header X-Forwarded-For $remote_addr;

	    location / {
	        proxy_pass         http://127.0.0.1:8000;
	        proxy_set_header   Host $host;
	        proxy_set_header   X-Real-IP $remote_addr;
	        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
	        proxy_set_header   X-Forwarded-Host $server_name;
	        proxy_read_timeout  1200s;

	        # used for view/edit office file via Office Online Server
	        client_max_body_size 0;

	        access_log      /var/log/nginx/seahub.access.log;
	        error_log       /var/log/nginx/seahub.error.log;
	    }


	location /seafhttp {
	    rewrite ^/seafhttp(.*)$ $1 break;
	    proxy_pass http://127.0.0.1:8082;
	    client_max_body_size 0;
	    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
	    proxy_connect_timeout  36000s;
	    proxy_read_timeout  36000s;
	    proxy_send_timeout  36000s;
	    send_timeout  36000s;
	}


	location /media {
	    root /home/mohammad/seafile-server-latest/seahub;
		}
	}


Sprema se i izlazi.

Treba uključiti seafile virtual host i testirati konfiguraciju:

::

	ln -s /etc/nginx/sites-available/seafile /etc/nginx/sites-enabled/
	nginx -t

Treba se pobrinuti da nema nikakvih grešaka i ponovno se pokrene Nginx servis.

::

	systemctl restart nginx

Postavljanje Nginx-a za obrnuti proxy je završena.


4.6. Šesti korak je postavljanje Seafile Servera


Kako bi se pokrenuo Seafile pod Nginx web server domenom, treba urediti zadani 'seafile' konfiguracijski `ccnet servive`, `seafile server` i `seahub server`.

Prijavljujemo se sa korisnikom 'dofano' i putujemo u `conf/` direktorij.

::

	su - dofano
	cd conf/

Potrebno je sad urediti ccnet konfiguracijsku datoteku `ccnet.conf`.

::

	nano ccnet.conf

U liniji `SERVICE_URL`, treba promijeniti vrijednost domenskog imena sa HTTPS-om kao ispod:

::

	SERVICE_URL = https://stuffer.xyz

Sprema se i zatvara datoteka.

Nakon toga potrebno je urediti `seafile.conf` datoteku za konfiguraciju seafile servera.

::

	nano seafile.conf

Dodaje se 'host' linija gdje je vrijednost '127.0.0.1' localhost kao što je prikazano u nastavku:

::
	
	[fileserver]
	host = 127.0.0.1
	port = 8082

Sprema se i zatvara datoteka.

Na kraju, potrebno je i urediti datoteku `seahub_settings.py`

::

	nano seahub_settings.py

U liniji `FILE_SERVER_ROOT`, promijenimo vrijednost naziva domena sa HTTPS.

::

	FILE_SERVER_ROOT = 'https://cloud.stuffer.xyz/seafhttp'

Sprema se i zatvara datoteka.


4.7. Sedmi korak je pokretanje Seafile Servera kao servisa


Sad je potrebno kreirati novu skriptu servisa za seafile i seahub. Idemo do `/etc/systemd/system` direktorija i stvaramo novu servisnu datoteka `seafile.service`

::

	cd /etc/systemd/system/
	nano seafile.service

U nju zalijepimo sljedeću seafile skriptu.

::

	[Unit]
	Description=Seafile
	After=network.target mysql.service

	[Service]
	Type=forking
	ExecStart=/home/dofano/seafile-server/seafile.sh start
	ExecStop=/home/dofano/seafile-server/seafile.sh stop
	User=dofano
	Group=dofano

	[Install]
	WantedBy=multi-user.target

Sprema se i zatvara datoteka.

Nakon toga stvara se datoteka seahub servisa `seahub.service`

::

	nano seahub.service

U tu datoteku zalijepimo sljedeći tekst.

::

	[Unit]
	Description=Seafile hub
	After=network.target seafile.service

	[Service]
	Type=forking
	ExecStart=/home/dofano/seafile-server/seahub.sh start
	ExecStop=/home/dofano/seafile-server/seahub.sh stop
	User=dofano
	Group=dofano

	[Install]
	WantedBy=multi-user.target


Sprema se i zatvara datoteka. Ponovno pokrećemo systemd sustav.

::

	systemctl daemon-reload

Pokreću se seafile i seahub servisi.

::

	systemctl start seafile
	systemctl start seahub

Postavlja se da se pokreću servisi prilikom pokretanja sustava.

::

	systemctl enable seafile
	systemctl enable seahub


Seafile i seahub servisi su aktivni i rade. Provjerava se sljedećim naredbama:

::

	systemctl status seafile
	systemctl status seahub
 
	netstat -plntu


S obzirom da mo prije već postavljali postavke vatrozida, sada nam preostaje testiranje.


4.8. Osmi korak je testiranje


Otvara se željeni web preglednik i utipkava se seafile server instalacijki link:

::

	https://stuffer.xyz

Staranica se automatski odvodi na sigurnu HTTPS stranicu za prijavu (*login*). Utipkavanjem vlastitih podataka koji su prethodno postavljeni, ulazi se u Seafile kontrolnu ploču (*dashboard*).

Seafile server na Nginx web serveru je uspješno pokrenut!

5. Instaliranje i zaštita `Memcached-a <https://www.digitalocean.com/community/tutorials/how-to-install-and-secure-memcached-on-ubuntu-16-04>`_

------------------------------------------------------------------------------------------------------------------------------------------------

Preostalo je još instalirati Memchached. Memcached je sustav za upravljanje predmemorijom i može optimizirati pozadnisku bazu podataka na način da privremeno sprema informacije u memoriju dobivajući često zahtjevane zapis. Na taj način se smanjuje broj izravnih zahtjeva prema bazi podataka.

S obzirom da Memcached pridonosi tome da se brani od napada ako nisu dobri postavljeni, važno je zaštiti Memcached server. Što će biti vidljivo u nastavku.

5.1. Instalacija Memcache-a

Memcache se može instalirati izravno s Ubuntu repozirotija:

::

	sudo apt-get update
	sudo apt-get install memcached

Također, može se instalirati `libmemcached-tools`, knjižnica koji pruža nekoliko alata za rad na Memcache serveru:

::

	sudo apt-get install libmemcached-tools

Memcached je sad instaliran na serveru skupa s njegovim servisima koji će pomoći pri testiranju. Prelazimo na sigurnost u sljedećim koracima.

5.2. Zaštita Memcache konfiguracijskih postavki

Za osigurati da Memcache sluša lokalno sučelje `127.0.0.1`, treba se provjeriti zadane postavke u konfiguracijskim datotekama koje se nalaze `/etc/memcached.conf`. Trenutna verzija koja se isporučuje s Ubuntu-om i Debian-om ima `-l` parametar postavljen na lokalno sučelje koje brani napade iz mreže. Postavka se može provjeriti u nastavku na adresi `/etc/memcached.conf` sa `nano`:

::

	sudo nano /etc/memcached.conf

Za inspekciju postavki sučelja, potrebno je naći sljedeće linije:

::

	. . .
	-l 127.0.0.1

Ako se vide zadane postavke `-l 127.0.0.1` tada nema potrebe za izmjenom. Ako se promijeni ta postavka za biti otvoreniji, tada je dobra ideja isključiti UDP, jer vjerojatnije je da će biti iskorišten u napadima uskraćivanja usluge. Za isključivanje UDP (TCP ostaje kako je), dodaje se opcija:

::

	. . .
	-U 0

Sprema se i zatvara datoteka.
Ponovno se pokreće Memcached servis kako bi se pohranile promjene:

::

	sudo systemctl restart memcached

Provjerava se da je trenutačno vezan za lokalno sučelje i sluša samo TCP veze:

::

	sudo netstat -plunt

Trebao bi biti vidljiv sljedeći ispis:

::

	Output
	Active Internet connections (only servers)
	Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
	. . .
	tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      2383/memcached
	. . .

Što potvrđuje da `memcached` vezan za adresu 127.0.0.1 koristeći samo TCP.





