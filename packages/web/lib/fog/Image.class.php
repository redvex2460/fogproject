<?php
class Image extends FOGController {
    // Table
    public $databaseTable = 'images';
    // Name -> Database field name
    public $databaseFields = array(
        'id' => 'imageID',
        'name' => 'imageName',
        'description' => 'imageDesc',
        'path' => 'imagePath',
        'createdTime' => 'imageDateTime',
        'createdBy' => 'imageCreateBy',
        'building' => 'imageBuilding',
        'size' => 'imageSize',
        'imageTypeID' => 'imageTypeID',
        'imagePartitionTypeID' => 'imagePartitionTypeID',
        'osID' => 'imageOSID',
        'size' => 'imageSize',
        'deployed' => 'imageLastDeploy',
        'format' => 'imageFormat',
        'magnet' => 'imageMagnetUri',
        'protected' => 'imageProtect',
        'compress' => 'imageCompress',
    );
    // Additional Fields
    public $additionalFields = array(
        'hosts',
        'hostsnotinme',
        'storageGroups',
        'storageGroupsnotinme',
    );
    public function isValid() {
        return $this->get('id') && $this->get('name');
    }
    // Overrides
    private function loadHosts() {
        if (!$this->isLoaded('hosts') && $this->get('id')) {
            $this->set('hosts',array_unique($this->getClass('HostManager')->find(array('imageID'=>$this->get('id')),'','','','','','','id')));
            $this->set('hostsnotinme',array_unique($this->getClass('HostManager')->find(array('imageID'=>$this->get('id')),'','','','','',true,'id')));
        }
        return $this;
    }
    private function loadGroups() {
        if (!$this->isLoaded('storageGroups') && $this->get('id')) {
            $StorageGroupIDs = array_unique($this->getClass('ImageAssociationManager')->find(array('imageID'=>$this->get('id')),'','','','','','','storageGroupID'));
            $this->set('storageGroups',$StorageGroupIDs);
            $this->set('storageGroupsnotinme',array_unique($this->getClass('StorageGroupManager')->find(array('id'=>$StorageGroupIDs),'','','','','',true,'id')));
        }
        return $this;
    }
    public function get($key = '') {
        if (in_array($this->key($key),array('hosts','hostsnotinme'))) $this->loadHosts();
        else if (in_array($this->key($key),array('storageGroups','storageGroupsnotinme'))) $this->loadGroups();
        return parent::get($key);
    }
    public function set($key, $value) {
        if ($this->key($key) == 'hosts') $this->loadHosts();
        else if ($this->key($key) == 'storageGroups')$this->loadGroups();
        // Set
        return parent::set($key, $value);
    }
    public function remove($key, $object) {
        if ($this->key($key) == 'hosts') $this->loadHosts();
        else if ($this->key($key) == 'storageGroups') $this->loadGroups();
        // Remove
        return parent::remove($key, $object);
    }
    public function save() {
        parent::save();
        if ($this->isLoaded('hosts')) {
            // Destroy only the removed elements
            $DBHostIDs = $this->getSubObjectIDs('Host',array('imageID'=>$this->get('id')),'hostID');
            $RemoveHostIDs = array_diff((array)$this->get('hosts'),(array)$DBHostIDs);
            $this->getClass('HostManager')->update(array('imageID'=>$this->get('id')),'',array('imageID'=>0));
            $DBHostIDs = $this->getSubObjectIDs('Host',array('imageID'=>$this->get('id')),'hostID');
            $HostIDs = array_diff((array)$this->get('hosts'),(array)$DBHostIDs);
            unset($RemoveHostIDs);
            $this->getClass('HostManager')->update(array('id'=>$HostIDs),'',array('imageID'=>$this->get('id')));
        }
        if ($this->isLoaded('storageGroups')) {
            // Destroy only the removed elements
            $DBGroupIDs = $this->getSubObjectIDs('ImageAssociation',array('imageID'=>$this->get('id')),'storageGroupID');
            $RemoveGroupIDs = array_diff($DBGroupIDs,(array)$this->get('storageGroups'));
            $this->getClass('ImageAssociationManager')->destroy(array('imageID'=>$this->get('id'),'storageGroupID'=>$RemoveGroupIDs));
            $DBGroupIDs = $this->getSubObjectIDs('ImageAssociation',array('imageID'=>$this->get('id')),'storageGroupID');
            $Groups = array_diff((array)$this->get('storageGroups'),(array)$DBGroupIDs);
            unset($RemoveGroupIDs);
            // Create Assoc
            foreach((array)$Groups AS $i => &$Group) {
                $this->getClass('ImageAssociation')
                    ->set('imageID',$this->get('id'))
                    ->set('storageGroupID',$Group)
                    ->save();
            }
            unset($Group);
        }
        return $this;
    }
    public function load($field = 'id') {
        parent::load($field);
        $methods = get_class_methods($this);
        foreach($methods AS $i => &$method) {
            if (strlen($method) > 5 && strpos($method,'load')) $this->$method();
        }
        unset($method);
        return $this;
    }
    public function add($key,$value) {
        if ($this->key($key) == 'hosts') $this->loadHosts();
        else if ($this->key($key) == 'storageGroups') $this->loadGroups();
        return parent::add($key,$value);
    }
    public function addGroup($addArray) {
        // Add
        $this->set('hosts',array_unique(array_merge((array)$this->get('storageGroups'),(array)$addArray)));
        // Return
        return $this;
    }
    public function removeGroup($removeArray) {
        // Iterate array (or other as array)
        $this->set('hosts',array_unique(array_diff((array)$this->get('storageGroups'),(array)$removeArray)));
        // Return
        return $this;
    }
    public function addHost($addArray) {
        // Add
        $this->set('hosts',array_unique(array_merge((array)$this->get('hosts'),(array)$addArray)));
        // Return
        return $this;
    }
    public function removeHost($removeArray) {
        // Iterate array (or other as array)
        $this->set('hosts',array_unique(array_diff((array)$this->get('hosts'),(array)$removeArray)));
        // Return
        return $this;
    }
    public function getStorageGroup() {
        $StorageGroup = $this->getClass('StorageGroup',current((array)$this->get('storageGroups')));
        if (!$StorageGroup->isValid()) {
            $this->add('storageGroups',@min($this->getClass('StorageGroupManager')->find('','','','','','','','id')));
            $StorageGroup = $this->getClass('StorageGroup',current((array)$this->get('storageGroups')));
        }
        return $StorageGroup;
    }
    public function getOS() {
        return $this->getClass('OS',$this->get('osID'));
    }
    public function getImageType() {
        return $this->getClass('ImageType',$this->get('imageTypeID'));
    }
    public function getImagePartitionType() {
        if ($this->get('imagePartitionTypeID')) $IPT = $this->getClass('ImagePartitionType',$this->get('imagePartitionTypeID'));
        else $IPT = $this->getClass('ImagePartitionType',1);
        return $IPT;
    }
    public function deleteFile() {
        if ($this->get('protected')) throw new Exception($this->foglang['ProtectedImage']);
        $SN = $this->getStorageGroup()->getMasterStorageNode();
        $SNME = ($SN->get('isEnabled') == 1);
        if (!$SNME)	throw new Exception($this->foglang['NoMasterNode']);
        $ftphost = $SN->get('ip');
        $ftpuser = $SN->get('user');
        $ftppass = $SN->get('pass');
        $ftproot = rtrim($SN->get('ftppath'),'/').'/'.$this->get('path');
        $this->FOGFTP
            ->set('host',$ftphost)
            ->set('username',$ftpuser)
            ->set('password',$ftppass)
            ->connect();
        if(!$this->FOGFTP->delete($ftproot)) throw new Exception($this->foglang['FailedDeleteImage']);
    }
}
/* Local Variables: */
/* indent-tabs-mode: t */
/* c-basic-offset: 4 */
/* tab-width: 4 */
/* End: */
