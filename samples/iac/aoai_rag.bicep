// Canonical Bicep sample — Azure OpenAI + RAG stack.
// Use:  atms scan samples/iac/aoai_rag.bicep

// VNet boundary
resource prodVnet 'Microsoft.Network/virtualNetworks@2022-09-01' = {
  name: 'prod-vnet'
  location: 'eastus'
  properties: {
    addressSpace: { addressPrefixes: [ '10.0.0.0/16' ] }
  }
}

// API tier
resource apim 'Microsoft.ApiManagement/service@2022-09-01-preview' = {
  name: 'prod-apim'
  location: 'eastus'
  sku: { name: 'Developer', capacity: 1 }
}

resource appPlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: 'prod-plan'
  location: 'eastus'
  sku: { name: 'P1v3', tier: 'PremiumV3' }
}

resource webapp 'Microsoft.Web/sites@2022-03-01' = {
  name: 'prod-web'
  location: 'eastus'
  properties: {
    serverFarmId: appPlan.id
  }
}

resource ragOrchestrator 'Microsoft.Web/sites@2022-03-01' = {
  name: 'rag-orchestrator'
  kind: 'functionapp'
  location: 'eastus'
  properties: {
    serverFarmId: appPlan.id
  }
}

// AI services
resource aoai 'Microsoft.CognitiveServices/accounts@2023-05-01' = {
  name: 'prod-aoai'
  location: 'eastus'
  sku: { name: 'S0' }
  kind: 'OpenAI'
}

resource cogSearch 'Microsoft.Search/searchServices@2022-09-01' = {
  name: 'prod-search'
  location: 'eastus'
  sku: { name: 'standard' }
}

// Storage / data
resource stg 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'prodstorage'
  location: 'eastus'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}

resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2022-08-15' = {
  name: 'prod-cosmos'
  location: 'eastus'
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
  }
}

resource sqlSrv 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: 'prod-sql'
  location: 'eastus'
  properties: {
    administratorLogin: 'admin'
    administratorLoginPassword: 'redacted'
  }
}

resource redis 'Microsoft.Cache/Redis@2022-06-01' = {
  name: 'prod-cache'
  location: 'eastus'
  properties: {
    sku: { name: 'Standard', family: 'C', capacity: 1 }
  }
}

// Identity / secrets
resource kv 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: 'prod-kv'
  location: 'eastus'
  properties: {
    tenantId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    sku: { name: 'standard', family: 'A' }
  }
}

resource mi 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'prod-mi'
  location: 'eastus'
}

// Monitoring
resource la 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'prod-logs'
  location: 'eastus'
  properties: {
    sku: { name: 'PerGB2018' }
  }
}

resource appins 'Microsoft.Insights/components@2020-02-02' = {
  name: 'prod-ai'
  location: 'eastus'
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: la.id
  }
}

// Networking
resource appGw 'Microsoft.Network/applicationGateways@2022-09-01' = {
  name: 'prod-appgw'
  location: 'eastus'
}

resource frontDoor 'Microsoft.Network/frontDoors@2021-06-01' = {
  name: 'prod-frontdoor'
  location: 'global'
}
