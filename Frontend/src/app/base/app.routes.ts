import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginCallback } from '../Views/login-callback/login-callback';

export const routes: Routes = [
  { path: '', component: LoginCallback },
  // { path: 'create-event', component: CreateEventComponent },

];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
