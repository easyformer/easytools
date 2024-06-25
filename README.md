
> pour éditer le fichier readme en markdown https://readme.easyformer.fr/


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

installation_gitlab() { 

#helpDescription="Installe et configure GitLab pour la gestion de code source"

#categoryMenu="apps" 

#nameMenu="Installation de GitLab"

#commutatorLetter="g"

#commutatorWord="install-gitlab"

    echo -e "Installation de GitLab..."
    
    apt-get install -y gitlab
    
    # Commandes pour configurer GitLab
    
}

