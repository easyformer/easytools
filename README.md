
> Pour éditer le fichier readme en markdown https://readme.easyformer.fr/


# easytools
Script de personnalisation et d'administration de linux en bash.

Le script Easytools génère automatiquement :
 - L'aide utilisateur,
 - L'aide développeur,
 - Le menu principal,
 - Les sous-menus,
 - Les commutateurs de lancement par lettre,
 - et les commutateurs de lancement par mot.

## Voici un exemple de fonction à intégrer dans le code pour ce faire:
> Les commentaires sont obligatoires...

**installation_gitlab(){**

**#helpDescription=**"Installe et configure GitLab pour la gestion de code source"

**#categoryMenu=**"apps" 

**#nameMenu=**"Installation de GitLab"

**#commutatorLetter=**"g"

**#commutatorWord=**"install-gitlab"

    echo -e "Installation de GitLab..."
    
    apt-get install -y gitlab
    
**}**


> Voici les catégories de menu que vous pouvez mettre (dans #categoryMenu) :
> 
> **"admin"**, **"proxmox"**, **"parameter"**, **"authentication"**, **"mail"**, **"security"**, **"agent"** et **"apps"**

## pour en ajouter utiliser la variable suivante:

>**optionsMainMenu=(**
>
>    "Administration" **"admin"**
>
>    "Administration de Proxmox" **"proxmox"**
> 
>    "Parametrage" **"parameter"**
> 
>    "Authentification" **"authentication"**
> 
>    "Messagerie" **"mail"**
> 
>    "Sécurité" **"security"**
> 
>    "Supervision" **"agent"**
> 
>    "Installation" **"apps"**
>
>    "[Manuel d'utilisation]" "help"
> 
>    "[Quitter]" "quit"
> 
>**)**

## Vous pouvez simplement ajouter des fonctions avec votre IA préférée en tappant:

>Peux-tu me générer une fonction en shell pour ubuntu respectant la structure suivante:
>
>nom_de_la_fonction(){
>
>#helpDescription="mettre ici une explication de ce que cela fait"
>
>#categoryMenu="admin"
>
>#nameMenu="Mettre ici le nom de la fonction telle qu'elle sera écrite dans le menu"
>
>#commutatorLetter="Mettre ici la lettre qui sera utilisé comme commutateur de lancement"
>
>#commutatorWord="Mettre ici un mot ou groupe de mots sans espaces avec des underscores si'il le faut et qui sera utilisé comme commutateur de lancement"
>
>    ## Mettre le code demmandé ici ##
>    
>}
>
>Seules les catégories suivantes doivent être utilisées "admin", "proxmox", "parameter", "authentication", "mail", "security", "agent" et "apps".

Le script devra faire ...



