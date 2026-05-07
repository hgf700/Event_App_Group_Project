import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginCallback } from '../Views/login-callback/login-callback';
import { Home } from '../Views/home/home';
import { LoginUser } from '../Views/login-user/login-user';
import { RegisterUser } from '../Views/register-user/register-user';
import { SeedDatabase } from '../Views/seed-database/seed-database';
import { GetEvents } from '../Views/get-events/get-events';
import { SubEventDetails } from '../Views/sub-event-details/sub-event-details';




export const routes: Routes = [
  { path: '', component: Home },
  { path: 'login-user', component: LoginUser },
  { path: 'register-user', component: RegisterUser },
  { path: 'login-callback', component: LoginCallback },
  { path: 'seed-database', component: SeedDatabase },
  { path: 'get-events', component: GetEvents },
  { path: 'sub-event-details/:id', component: SubEventDetails },



];


@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
