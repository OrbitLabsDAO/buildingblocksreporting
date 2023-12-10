 
Name

title

Description

The title variable is used to contain the bread crumbs

example

title = `<a id="" href="/{{env.LEVEL1NAME}}/">{{env.LEVEL1NAME | capitalize }}</a> / ${di.name} / <span>{{title}}</span>`;    

Name

lookUps

Description

Example

table = Table name
key = ?
foreignKey = 
name
value

let lookUps = [
                  {
                     "table":"payment_types",
                     "key":"paidBy",
                     "foreignKey":"name",
                     "value":""
                  }
               ]



let formatFields = [
                     {
                        "field":"amountInternational",
                        "function":"formatCurencyUSD(tmpValue)"
                     }
                  ]


let theFields = "{% for field in fields %}{% if loop.last %}{{ field }}{% else %}{{ field }},{% endif %}{% endfor %}";


const theSettings = {
   "checkAdmin":0,
   "tableSchema":0,
   "allowOnlyOne":0,
   "editButton":1,
   "deleteButton":1,
   "customButton":"",
   "customSelect":"",
   "localLookUp":"",
   "localReplace":"",
   "table":"rental_cost",
   "formatFields":formatFields,
   "fields":theFields,
   "crumb":"{{ crumb }}",
   "foreignKey":"propertyId",
   "lookUps":"",
   "title":title,
   "orderBy":"DESC",
   "orderByField":"datePaid",
   "orderByTableId":4
}

