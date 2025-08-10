use sqlx::PgPool;
use crate::{DataError};

#[derive(sqlx::FromRow, serde::Deserialize)]
pub struct Recipe{
    pub id:i32,
    pub recipe_name:String,
    pub about:String,
    pub ingridients:String,
    pub image_url:String
}

#[derive(sqlx::FromRow, serde::Deserialize, serde::Serialize)]
pub struct RecipeDetails {
    pub id: i32,
    pub recipe_name: String,
    pub about: String,
    pub nutrition_per_100g_of_recipe: String,
    pub energy_kcal: f64,          // Changed from BigDecimal
    pub fat_g: f64,                // Changed from BigDecimal
    pub carbohydrates_g: f64,      // Changed from BigDecimal
    pub proteins_g: f64,           // Changed from BigDecimal
    pub fibre_g: f64,              // Changed from BigDecimal
    pub vitamin_a_mcg: i32,
    pub iron_mg: f64,              // Changed from BigDecimal
    pub zinc_mg: f64,              // Changed from BigDecimal
    pub f_factor_est: f64,         // Changed from BigDecimal
    pub image_url: String,
    pub ingredients: String,
    pub supplementary_ingredients: String,
    pub supplementary_instructions: String,
    pub parsed_ingredients_array: Vec<String>,
    pub preparation_steps:Vec<String>
}

pub async fn get_recipes(pool:&PgPool,cursor:i32)->Result<Vec<Recipe>,DataError>{
    let recipes:Vec<Recipe>=sqlx::query_as(
        "SELECT id,recipe_name,about,ingridients,image_url FROM kenyan_food_recipes WHERE id>$1 ORDER BY id ASC LIMIT 10;"
    )
    .bind(cursor)
    .fetch_all(pool)
    .await?;
    Ok(recipes)
}

pub async fn get_recipe_info(pool:&PgPool,id:i32)->Result<RecipeDetails,DataError>{
    let recipe=sqlx::query_as!(
        RecipeDetails,
        "SELECT id,
            recipe_name,
            about,
            nutrition_per_100g_of_recipe,
            energy_kcal,
            fat_g,
            carbohydrates_g,
            proteins_g,
            fibre_g,
            vitamin_a_mcg,
            iron_mg,
            zinc_mg,
            f_factor_est,
            image_url,
            ingredients,
            supplementary_ingredients,
            supplementary_instructions,
            parsed_ingredients_array,
            preparation_steps
             FROM kenyan_food_recipes WHERE id=$1",
        id
    )
    .fetch_one(pool)
    .await?;
    Ok(recipe)

}


#[derive(sqlx::FromRow, serde::Deserialize, serde::Serialize)]
pub struct RecipeSearchResult {
    pub id: i32,
    pub recipe_name: String,
    pub about: String,
    pub image_url: String,
    pub rank: Option<f32>, // Search relevance score
}

// Add this search function
pub async fn search_recipes(
    pool: &PgPool, 
    query: String, 
) -> Result<Vec<Recipe>, DataError> {
    let recipes = sqlx::query_as!(
        Recipe,
        r#"
        SELECT 
            id,
            recipe_name,
            about,
            ingridients,
            image_url
        FROM kenyan_food_recipes 
        WHERE search_vector @@ plainto_tsquery('english', $1)
        ORDER BY ts_rank(search_vector, plainto_tsquery('english', $1)) DESC
        LIMIT 10
        "#,
        query
    )
    .fetch_all(pool)
    .await?;
    Ok(recipes)
}