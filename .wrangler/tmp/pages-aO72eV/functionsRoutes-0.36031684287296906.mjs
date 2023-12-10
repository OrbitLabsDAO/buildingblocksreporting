import { onRequestPost as __api_admin_account_js_onRequestPost } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/admin/account.js"
import { onRequestGet as __api_admin_email_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/admin/email.js"
import { onRequestGet as __api_admin_image_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/admin/image.js"
import { onRequestGet as __api_database_lookUp_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/database/lookUp.js"
import { onRequestGet as __api_database_schema_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/database/schema.js"
import { onRequestDelete as __api_database_table_js_onRequestDelete } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/database/table.js"
import { onRequestGet as __api_database_table_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/database/table.js"
import { onRequestPost as __api_database_table_js_onRequestPost } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/database/table.js"
import { onRequestPut as __api_database_table_js_onRequestPut } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/database/table.js"
import { onRequestGet as __api_properties_crowdfund_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/properties/crowdfund.js"
import { onRequestPost as __api_properties_crowdfund_js_onRequestPost } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/properties/crowdfund.js"
import { onRequestGet as __api_properties_distributions_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/properties/distributions.js"
import { onRequestGet as __api_properties_report_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/properties/report.js"
import { onRequestGet as __api_settings_js_onRequestGet } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/settings.js"
import { onRequestPut as __api_settings_js_onRequestPut } from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/functions/api/settings.js"

export const routes = [
    {
      routePath: "/api/admin/account",
      mountPath: "/api/admin",
      method: "POST",
      middlewares: [],
      modules: [__api_admin_account_js_onRequestPost],
    },
  {
      routePath: "/api/admin/email",
      mountPath: "/api/admin",
      method: "GET",
      middlewares: [],
      modules: [__api_admin_email_js_onRequestGet],
    },
  {
      routePath: "/api/admin/image",
      mountPath: "/api/admin",
      method: "GET",
      middlewares: [],
      modules: [__api_admin_image_js_onRequestGet],
    },
  {
      routePath: "/api/database/lookUp",
      mountPath: "/api/database",
      method: "GET",
      middlewares: [],
      modules: [__api_database_lookUp_js_onRequestGet],
    },
  {
      routePath: "/api/database/schema",
      mountPath: "/api/database",
      method: "GET",
      middlewares: [],
      modules: [__api_database_schema_js_onRequestGet],
    },
  {
      routePath: "/api/database/table",
      mountPath: "/api/database",
      method: "DELETE",
      middlewares: [],
      modules: [__api_database_table_js_onRequestDelete],
    },
  {
      routePath: "/api/database/table",
      mountPath: "/api/database",
      method: "GET",
      middlewares: [],
      modules: [__api_database_table_js_onRequestGet],
    },
  {
      routePath: "/api/database/table",
      mountPath: "/api/database",
      method: "POST",
      middlewares: [],
      modules: [__api_database_table_js_onRequestPost],
    },
  {
      routePath: "/api/database/table",
      mountPath: "/api/database",
      method: "PUT",
      middlewares: [],
      modules: [__api_database_table_js_onRequestPut],
    },
  {
      routePath: "/api/properties/crowdfund",
      mountPath: "/api/properties",
      method: "GET",
      middlewares: [],
      modules: [__api_properties_crowdfund_js_onRequestGet],
    },
  {
      routePath: "/api/properties/crowdfund",
      mountPath: "/api/properties",
      method: "POST",
      middlewares: [],
      modules: [__api_properties_crowdfund_js_onRequestPost],
    },
  {
      routePath: "/api/properties/distributions",
      mountPath: "/api/properties",
      method: "GET",
      middlewares: [],
      modules: [__api_properties_distributions_js_onRequestGet],
    },
  {
      routePath: "/api/properties/report",
      mountPath: "/api/properties",
      method: "GET",
      middlewares: [],
      modules: [__api_properties_report_js_onRequestGet],
    },
  {
      routePath: "/api/settings",
      mountPath: "/api",
      method: "GET",
      middlewares: [],
      modules: [__api_settings_js_onRequestGet],
    },
  {
      routePath: "/api/settings",
      mountPath: "/api",
      method: "PUT",
      middlewares: [],
      modules: [__api_settings_js_onRequestPut],
    },
  ]