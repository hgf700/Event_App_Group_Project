import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginCallback } from '../Views/login-callback/login-callback';
import { Home } from '../Views/home/home';
import { LoginUser } from '../Views/login-user/login-user';
import { RegisterUser } from '../Views/register-user/register-user';
import { SeedDatabase } from '../Views/seed-database/seed-database';
import { GetEvents } from '../Views/get-events/get-events';
import { SubEventDetails } from '../Views/sub-event-details/sub-event-details';
import { PaymentSuccess } from '../Views/payment-success/payment-success';
import { PaymentFailed } from '../Views/payment-failed/payment-failed';
import { SearchAndImportEvents } from '../Views/search-and-import-events/search-and-import-events';
import { EditUser } from '../Views/edit-user/edit-user';
import { UserTickets } from '../Views/user-tickets/user-tickets';

export const routes: Routes = [
  { path: '', component: Home },
  { path: 'login-user', component: LoginUser },
  { path: 'register-user', component: RegisterUser },
  { path: 'login-callback', component: LoginCallback },
  { path: 'seed-database', component: SeedDatabase },
  { path: 'get-events', component: GetEvents },
  { path: 'sub-event-details/:id', component: SubEventDetails },
  { path: 'payment-success', component: PaymentSuccess },
  { path: 'payment-failed', component: PaymentFailed },
  { path: 'search-and-import-events', component: SearchAndImportEvents },
  { path: 'edit-user', component: EditUser },
  { path: 'user-tickets', component: UserTickets },
  
  
  
  
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
