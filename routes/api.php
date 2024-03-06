<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthenticationController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

//Notes: 
//https://medium.com/@kingasiadavid41/laravel-10-api-authentication-using-passport-154137cbce31


//Notes: V Good
//https://www.allphptricks.com/laravel-10-rest-api-using-passport-authentication/


Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::group(['namespace' => 'Api', 'prefix' => 'v1'], function () {
  Route::post('login', [AuthenticationController::class, 'login']);
  Route::post('register', [AuthenticationController::class, 'register']);
  
  Route::post('logout', [AuthenticationController::class, 'logout'])->middleware('auth:api');
});




