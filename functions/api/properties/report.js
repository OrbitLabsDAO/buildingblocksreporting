export async function onRequestGet(context) {
    //build the paramaters
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context;
    //build the result
    let result = {}
    //get the search paramaters
    const { searchParams } = new URL(request.url);
    //get the id
    let id = searchParams.get('id');
    //check if there is a property id.
    if (id == null)
        return new Response(JSON.stringify({ error: "no property id" }), { status: 400 });
    //get the property
    const property = context.env.DB.prepare(`SELECT * from property where id = ${id}`);
    const propertyresult = await property.first();
    //check we have a result
    if (propertyresult == undefined)
        return new Response(JSON.stringify({ error: "no property found with that id" }), { status: 400 });

    //get the token for the property
    const token = context.env.DB.prepare(`SELECT * from property_token where propertyId = ${id}`);
    const tokenresult = await token.first();
    //get the owners for the property

    console.log(tokenresult)
    if (tokenresult != undefined) {
        const owners = context.env.DB.prepare(`SELECT property_owner.id,property_owner.tokenAmount,user.name,user.email from property_owner LEFT JOIN user ON property_owner.userId = user.id where property_owner.propertyTokenId = ${tokenresult.id}`);
        const ownersresults = await owners.all();
        //get the owners for the  distributions
        const distributions = context.env.DB.prepare(`SELECT * from property_distribution where propertyId = ${id}`);
        const distributionsresults = await distributions.all();
        result.owners = ownersresults.results;
        result.distributions = distributionsresults.results;
    } else {
        result.owners = {}
        result.distributions = {}
    }
    //get the agreement
    const agreement = context.env.DB.prepare(`SELECT * from rental_agreement where propertyId = ${id}`);
    const agreementresults = await agreement.all();
    //get the costs
    const costs = context.env.DB.prepare(`SELECT * from rental_cost where propertyId = ${id}`);
    const costsresults = await costs.all();
    //get the payments
    const payments = context.env.DB.prepare(`SELECT * from rental_payment where propertyId = ${id}`);
    const paymentsresults = await payments.all();
    //debug
    //console.log(propertyresult);
    //console.log(tokenresult);
    //console.log(costsresults);
    //console.log(paymentsresults.results);


    result.property = propertyresult;
    result.token = tokenresult;
    result.agreements = agreementresults.results;
    result.costs = costsresults.results;
    result.payments = paymentsresults.results;
    //return it
    return new Response(JSON.stringify(result), { status: 200 });
}