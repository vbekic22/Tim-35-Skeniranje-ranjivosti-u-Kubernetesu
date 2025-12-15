## 5. Mitigation and Hardening of the Kubernetes Cluster

Ovaj dokument opisuje sve konkretne korake mitigacije i hardeninga koji su provedeni nad postojećom aplikacijom i Kubernetes klasterom. Svaka podsekcija prvo ukratko objašnjava izvorni (namjerno ranjivi) dizajn, a zatim prikazuje uvedene promjene i sigurnosne dobitke.

---

## 5.1 Apply Security Best Practices – Update container images to non-vulnerable versions

### 5.1.1 Izvorno stanje

- **Backend `Dockerfile`**
  - Koristio je baznu sliku `node:16` u build i production stageu.
  - U komentaru je eksplicitno naznačeno da je riječ o **starijoj verziji Node.js 16** s poznatim ranjivostima (npr. CVE-2022-32212, CVE-2022-32213, itd.).

- **Frontend `Dockerfile`**
  - Build stage se temeljio na `node:16`.
  - Production stage je koristio `nginx:1.16`, što je **EOL verzija** Nginxa s više javno poznatih sigurnosnih problema.

- **MongoDB u Kubernetesu**
  - `mongodb-deployment.yaml` koristio je:
    - `image: mongo:4.0`
  - U komentaru je naznačeno da se radi o verziji s poznatim CVE-ovima (npr. CVE-2020-7928, CVE-2021-20329).

### 5.1.2 Uvedene promjene

- **Backend `Dockerfile`**
  - Zamijenjena je bazna slika:
    - Prije:
      - `FROM node:16 AS builder`
      - `FROM node:16`
    - Sada:
      - `FROM node:20 AS builder`
      - `FROM node:20`
  - Node 20 je **trenutni LTS** i aktivno se održava sigurnosnim zakrpama, za razliku od starog Node 16.

- **Frontend `Dockerfile`**
  - Build stage:
    - Prije: `FROM node:16 AS builder`
    - Sada: `FROM node:20 AS builder`
  - Production (Nginx) stage:
    - Prije: `FROM nginx:1.16`
    - Sada: `FROM nginx:1.27`
  - Time je frontend stack prebačen na **novije, podržane verzije** Node.js i Nginxa.

- **MongoDB deployment (`mongodb-deployment.yaml`)**
  - Zamijenjena je verzija:
    - Prije: `image: mongo:4.0`
    - Sada: `image: mongo:7.0`
  - MongoDB 7.0 je podržana verzija s redovitim sigurnosnim zakrpama, dok 4.0 ima više javno poznatih ranjivosti.

### 5.1.3 Sigurnosni učinak

- Smanjena je površina napada uklanjanjem **zastarjelih i ranjivih base image-ova**.
- Korištenjem podržanih LTS/novijih verzija (Node 20, Nginx 1.27, MongoDB 7.0) osigurano je:
  - redovito dobivanje sigurnosnih zakrpa,
  - mitigacija poznatih CVE-ova prisutnih u starim verzijama,
  - bolja osnova za daljnji hardening (RBAC, NetworkPolicy, Pod Security).

---

## 5.2 Implement Kubernetes Security Policies – RBAC (Role-Based Access Control)

### 5.2.1 Izvorno stanje (ranjivi RBAC)

Datoteka `rbac-vulnerable.yaml` definirala je izrazito preširoke privilegije:

- **ServiceAccount**
  - `vulnerable-service-account` u namespaceu `chat-app`.

- **Role `vulnerable-role` (namespace-scoped)**
  - `apiGroups: ["*"]`, `resources: ["*"]`, `verbs: ["*"]`  
    → praktički administratorski pristup nad svim resursima u namespaceu.
  - Dodatno: puna prava nad `secrets`, `pods/exec`, `pods/portforward`.

- **RoleBinding**
  - `vulnerable-role` je vezan na `default` service account u namespaceu `chat-app`.

- **ClusterRole `vulnerable-cluster-role`**
  - `apiGroups: ["*"]`, `resources: ["*"]`, `verbs: ["*"]`
  - Puna prava nad `nodes`, `persistentvolumes`, `namespaces`, itd.

- **ClusterRoleBinding**
  - `vulnerable-cluster-role` je također vezan na service account `default` u `chat-app`.

Posljedica: svaki pod koji se vrti s default service accountom imao je **gotovo potpunu kontrolu nad cijelim klasterom**, što je izrazito nesigurno.

### 5.2.2 Uvedene promjene (RBAC hardening)

Uvedene su promjene u novoj datoteci `rbac-hardened.yaml` i u deployment manifestima:

- **Novi ServiceAccount-i**
  - `backend-sa` u namespaceu `chat-app`
  - `frontend-sa` u namespaceu `chat-app`
  - `mongodb-sa` u namespaceu `chat-app`

- **Nova uloga za backend – `backend-role`**
  - Scope: namespace `chat-app`
  - Pravila:
    - `apiGroups: [""]`
    - `resources: ["secrets"]`
    - `verbs: ["get"]`
  - Backend aplikacija treba samo pročitati tajne (npr. JWT secret, DB connection string) – ne treba kreirati, brisati ili mijenjati resurse u klasteru.

- **RoleBinding za backend – `backend-role-binding`**
  - Vezivanje:
    - `subjects`: `backend-sa`
    - `roleRef`: `backend-role`
  - Efekt: samo backend podovi koji koriste `backend-sa` dobivaju minimalni skup dozvola potreban za rad.

- **Frontend i MongoDB**
  - Dobivaju vlastite service account-e (`frontend-sa`, `mongodb-sa`) bez dodatnih uloga.
  - Oni ne trebaju komunicirati s Kubernetes API-jem, pa im nije potrebna nikakva dodatna RBAC dozvola.

- **Povezivanje ServiceAccount-a s Deploymentima**
  - `backend-deployment.yaml`:
    - U `spec.template.spec` dodano:
      - `serviceAccountName: backend-sa`
  - `frontend-deployment.yaml`:
    - U `spec.template.spec` dodano:
      - `serviceAccountName: frontend-sa`
  - `mongodb-deployment.yaml`:
    - U `spec.template.spec` dodano:
      - `serviceAccountName: mongodb-sa`

### 5.2.3 Sigurnosni učinak

- Uveden je princip **least privilege**:
  - Backend dobiva samo minimalno potrebne ovlasti (read-only pristup tajnama).
  - Frontend i baza nemaju nepotreban pristup Kubernetes API-ju.
- Uklonjeno je oslanjanje na `default` service account s potencijalno opasnim ClusterRole/Role vezanjem.
- Kompromitacija jednog poda više ne znači automatsko preuzimanje kontrole nad cijelim klasterom preko preširokih RBAC privilegija.

---

## 5.3 Implement Kubernetes Security Policies – Network Policies (ograničavanje prometa između podova)

### 5.3.1 Izvorno stanje (ranjive Network Policies)

Datoteka `network-policy-vulnerable.yaml` sadržavala je:

- NetworkPolicy `vulnerable-network-policy`:
  - `podSelector: {}` (cilja sve podove u namespaceu).
  - `policyTypes: [Ingress, Egress]`.
  - `ingress: - {}` i `egress: - {}` → efektivno:
    - **dopušta sav dolazni i odlazni promet** prema svim podovima.
  - Komentar jasno naglašava da ovo **poništava svrhu network policies**, jer ne postoji nikakva izolacija.

- Druga NetworkPolicy `misconfigured-blocking-policy`:
  - Nije dovršena (prazna `ingress/egress` sekcija), ostavljena kao primjer krive konfiguracije.

### 5.3.2 Uvedene promjene (NetworkPolicy hardening)

Uvedena je nova datoteka `network-policy-hardened.yaml` s politikama:

- **`default-deny-all`**
  - `podSelector: {}` i `policyTypes: [Ingress, Egress]`.
  - Ne definira `ingress` niti `egress` pravila → svi podovi u namespaceu `chat-app` imaju:
    - **blokiran sav ulazni i izlazni promet**, osim ako ga neka druga NetworkPolicy eksplicitno dozvoli.
  - Ovo implementira model **"default deny"**.

- **`allow-frontend-from-ingress`**
  - `podSelector.matchLabels: app: frontend-selec`
  - `policyTypes: [Ingress]`
  - `ingress` dopušta:
    - promet iz `ipBlock.cidr: 0.0.0.0/0` (korisnici izvana, preko Servica/Ingresa),
    - na portu `80/TCP`.
  - Time je frontend dostupan prema van, ali nije proizvoljno dostupan iz drugih podova osim ako su izričito dopušteni.

- **`allow-backend-from-frontend`**
  - `podSelector.matchLabels: app: back-selec`
  - `policyTypes: [Ingress]`
  - `ingress`:
    - dopušta promet samo iz podova s `app: frontend-selec`,
    - na portu `5001/TCP`.
  - Backend servis ne može biti direktno napadnut od drugih podova (npr. potencijalno kompromitiranih), već samo od frontenda.

- **`allow-mongodb-from-backend`**
  - `podSelector.matchLabels: app: mongodb-selec`
  - `policyTypes: [Ingress]`
  - `ingress`:
    - dopušta promet iz podova s `app: back-selec`,
    - na portu `27017/TCP`.
  - MongoDB baza ne može se direktno gađati ni iz frontenda ni iz drugih podova; sav legitimni promet. ide isključivo preko backend sloja.

### 5.3.3 Sigurnosni učinak

- Mrežna komunikacija je sada **strogo ograničena**:
  - Eksterni promet → samo na frontend (HTTP/80).
  - Frontend → samo backend (5001/TCP).
  - Backend → samo MongoDB (27017/TCP).
- Spriječeno je lateralno kretanje unutar namespacea (`east-west` promet) između nepovezanih podova.
- Potencijalno kompromitirani pod više ne može slobodno skenirati i napadati ostale servise u klasteru.

---

## 5.4 Pod Security Policies / Pod Security Admission – standardi sigurnosti za podove

### 5.4.1 Izvorno stanje (ranjive Pod Security postavke)

- U `pod-security-vulnerable.yaml` definiran je namespace:
  - `name: chat-app-insecure`
  - s labelama:
    - `pod-security.kubernetes.io/enforce: privileged`
    - `pod-security.kubernetes.io/audit: privileged`
    - `pod-security.kubernetes.io/warn: privileged`
- Profil **`privileged`** praktički **isključuje sigurnosna ograničenja**:
  - dopušta privileged kontejnere,
  - dopušta korištenje host resursa (hostPID, hostNetwork, hostPath),
  - ne inzistira na `runAsNonRoot`, ograničenim capability-jima, itd.

- Produkcijski namespace `chat-app` (`namespace.yaml`) uopće nije imao primijenjene Pod Security standarde.

### 5.4.2 Uvedene promjene (Pod Security hardening)

Stvoren je novi manifest `pod-security-hardened.yaml` koji definira:

- **Namespace `chat-app` s Pod Security Admission labelama:**
  - `pod-security.kubernetes.io/enforce: "restricted"`
  - `pod-security.kubernetes.io/audit: "restricted"`
  - `pod-security.kubernetes.io/warn: "restricted"`

Profil **`restricted`** je najstroži od standardnih profila i:

- **zabranjuje privileged kontejnere**,
- zahtijeva da se podovi izvode kao **ne-root korisnici** (ili barem da to bude moguće),
- ograničava Linux capability-je,
- zabranjuje opasne tipove volume-a (npr. proizvoljni `hostPath`),
- općenito nameće niz best practice pravila za pokretanje podova.

### 5.4.3 Sigurnosni učinak

- Umjesto da se sigurnost oslanja samo na ručne postavke u svakom Deploymentu, sada je:
  - **centralno nametnut** sigurnosni standard (`restricted`) za cijeli namespace `chat-app`.
- Podovi koji pokušaju:
  - vrtjeti se kao root bez razloga,
  - koristiti privileged mode,
  - koristiti opasne host resurse,
  - ili kršiti druga pravila profila `restricted`,
  bit će blokirani pri kreiranju ili će generirati upozorenja/audit zapise.

---

## 5.5 Sažetak provedenog hardeninga

- **Ažuriranje container image-ova**
  - Zamijenjeni su zastarjeli i ranjivi base image-ovi (Node 16, Nginx 1.16, MongoDB 4.0) s podržanim verzijama (Node 20, Nginx 1.27, MongoDB 7.0).

- **RBAC (Role-Based Access Control)**
  - Uvedeni su zasebni service account-i (`backend-sa`, `frontend-sa`, `mongodb-sa`).
  - Backend dobiva minimalne read-only ovlasti nad tajnama, frontend i baza nemaju pristup Kubernetes API-ju.
  - Uklonjeno je oslanjanje na `default` service account s administratorskim privilegijama.

- **Network Policies**
  - Implementiran je model **default deny** za sav promet u namespaceu `chat-app`.
  - Izričito su dozvoljeni samo legitimni tokovi prometa: korisnik → frontend, frontend → backend, backend → baza.

- **Pod Security Admission**
  - Namespace `chat-app` označen je kao `restricted`, što je najstroži sigurnosni profil.
  - Spriječeno je pokretanje podova koji odstupaju od sigurnosnih best practice-a (privileged, runAsRoot, opasni mountovi, itd.).

Kombinacijom ovih mjera značajno je smanjena površina napada, onemogućena horizontalna eskalacija unutar klastera i implementirani su ključni Kubernetes sigurnosni standardi za produkcijsko okruženje.

---

## 5.6 Evidencija promjena i njihovi učinci

Ovo poglavlje sažeto bilježi **gdje su promjene napravljene** i **kakav efekt imaju u realnom klasteru**, kako bi se mogle lako dokazati i reproducirati.

### 5.6.1 Promjene na container image-ovima

- **Backend**
  - Datoteka: `backend/Dockerfile`
  - Promjena: `node:16` → `node:20` (build i runtime stage).
  - Očekivani efekt:
    - Nova verzija backenda koristi ažurni Node runtime.
    - `docker history` i `docker inspect` nad izgrađenom slikom potvrđuju novi base image.

- **Frontend**
  - Datoteka: `frontend/Dockerfile`
  - Promjena:
    - Build: `node:16` → `node:20`
    - Serve: `nginx:1.16` → `nginx:1.27`
  - Očekivani efekt:
    - Frontend se servira preko novije verzije Nginxa.
    - `docker history` / `docker inspect` pokazuju nove base image-ove.

- **MongoDB**
  - Datoteka: `K8s-manifest/mongodb-deployment.yaml`
  - Promjena: `image: mongo:4.0` → `image: mongo:7.0`
  - Očekivani efekt:
    - `kubectl get pods -n chat-app -o wide` pokazuje nove MongoDB podove izgrađene iz verzije 7.0.
    - `kubectl describe pod ...` prikazuje ažurirani image.

### 5.6.2 RBAC – uloge i dozvole

- **Novi RBAC resursi**
  - Datoteka: `K8s-manifest/rbac-hardened.yaml`
  - Resursi:
    - `ServiceAccount`: `backend-sa`, `frontend-sa`, `mongodb-sa`
    - `Role`: `backend-role` (read-only pristup `secrets` u `chat-app`)
    - `RoleBinding`: `backend-role-binding`
  - Očekivani efekt:
    - `kubectl get sa -n chat-app` prikazuje nove service account-e.
    - `kubectl get role,rolebinding -n chat-app` prikazuje ograničenu ulogu i njeno vezanje.
    - Pokušaj korištenja `kubectl auth can-i` iz podova bez odgovarajućih ovlasti vraća `no` za zabranjene operacije.

- **Povezivanje s Deploymentima**
  - Datoteke:
    - `K8s-manifest/backend-deployment.yaml` → `serviceAccountName: backend-sa`
    - `K8s-manifest/frontend-deployment.yaml` → `serviceAccountName: frontend-sa`
    - `K8s-manifest/mongodb-deployment.yaml` → `serviceAccountName: mongodb-sa`
  - Očekivani efekt:
    - `kubectl describe pod ... -n chat-app` pokazuje koji se `ServiceAccount` koristi za pojedini pod.

### 5.6.3 Network Policies – mrežna izolacija

- **Nove politike**
  - Datoteka: `K8s-manifest/network-policy-hardened.yaml`
  - Resursi:
    - `NetworkPolicy/default-deny-all`
    - `NetworkPolicy/allow-frontend-from-ingress`
    - `NetworkPolicy/allow-backend-from-frontend`
    - `NetworkPolicy/allow-mongodb-from-backend`
  - Očekivani efekt:
    - `kubectl get networkpolicy -n chat-app` prikazuje sve navedene politike.
    - Ručni testovi (npr. `kubectl exec` iz drugih podova) pokazuju da:
      - nije moguće direktno kontaktirati backend ili MongoDB s neautoriziranih podova,
      - legitimni tokovi (frontend → backend, backend → MongoDB) funkcioniraju.

### 5.6.4 Pod Security Admission – standardi za podove

- **Primjena Pod Security standarda**
  - Datoteka: `K8s-manifest/pod-security-hardened.yaml`
  - Resurs:
    - Namespace `chat-app` s labelama:
      - `pod-security.kubernetes.io/enforce: "restricted"`
      - `pod-security.kubernetes.io/audit: "restricted"`
      - `pod-security.kubernetes.io/warn: "restricted"`
  - Očekivani efekt:
    - `kubectl get ns chat-app --show-labels` prikazuje primijenjene PSA labele.
    - Pokušaj pokretanja podova s nesigurnim postavkama (npr. `privileged`, `runAsUser: 0`, `hostNetwork: true`) rezultira:
      - odbijanjem kreiranja poda (enforce),
      - i/ili upozorenjima u `kubectl apply` izlazu (warn/audit).

Na ovaj način, za svaki hardening korak postoje jasni tragovi u YAML manifestima i očekivani tehnički učinci koji se mogu provjeriti u samom Kubernetes klasteru (`kubectl` naredbama i funkcionalnim testiranjem). 


