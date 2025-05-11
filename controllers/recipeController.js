const User = require('../models/User.js')
const Recipe = require('../models/Recipe.js')

const createRecipe = async (req, res) => {
  try {
    const user = await User.findById(req.body.author)
    // Returns the full user object
    const recipe = await Recipe.create(req.body)
    // The only way this works this simply is if the request body being sent properly matches your model
    user.recipes.push(recipe._id)
    user.save()
    res.redirect(`/recipes/${recipe._id}`)
    // This will be an EJS page later...
  } catch (error) {
    console.error('An error has occurred creating a recipe!', error.message)
  }
}

const getAllRecipes = async (req, res) => {
  try {
    const recipes = await Recipe.find({})
    // findAll returns an array of every document that matches the criteria. In this case, our options object is empty (so there's no criteria).
    res.render('./recipes/all.ejs', { recipes })
    // This will be an EJS page later...
  } catch (error) {
    console.error('An error has occurred getting all recipes!', error.message)
  }
}

const getRecipeById = async (req, res) => {
  try {
    const recipe = await Recipe.findById(req.params.id)
    res.render('./recipes/show.ejs', { recipe })
    // This will be an EJS page later...
  } catch (error) {
    console.error('An error has occurred getting a recipe!', error.message)
  }
}

const updateRecipeById = async (req, res) => {
  try {
    const recipe = await Recipe.findByIdAndUpdate(req.params.id, req.body, { new: true })
    // req.body overwrites any matching fields with the new values. Only the updated fields are necessary.
    res.redirect(`/recipes/${recipe._id}`)
    // This will be an EJS page later...
  } catch (error) {
    console.error('An error has occurred updating a recipe!', error.message)
  }
}

const deleteRecipeById = async (req, res) => {
  try {
    await Recipe.findByIdAndDelete(req.params.id)
    // No need to store this in a variable since it's being deleted
    res.render('./recipes/confirm.ejs')
    // This will be an EJS page later...
  } catch (error) {
    console.error('An error has occurred deleting a recipe!', error.message)
  }
}

module.exports = {
  createRecipe,
  getAllRecipes,
  getRecipeById,
  updateRecipeById,
  deleteRecipeById
}