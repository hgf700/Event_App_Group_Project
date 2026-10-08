import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginCallback } from '../Views/login-callback/login-callback';
import { Home } from '../Views/home/home';
import { LoginUser } from '../Views/login-user/login-user';
import { RegisterUser } from '../Views/register-user/register-user';
import { SeedDatabase } from '../Views/seed-database/seed-database';
import { GetEvents } from '../Views/get-events/get-events';
import { SubEventDetails } from '../Views/sub-event-details/sub-event-details';
import { PaymentStatus } from '../Views/payment-status/payment-status';
import { SearchAndImportEvents } from '../Views/search-and-import-events/search-and-import-events';
import { UserTickets } from '../Views/user-tickets/user-tickets';
import { EditUser } from '../Views/edit-user/edit-user';
import { EditUserEmail } from '../Views/edit-user-email/edit-user-email';
import { EditUserPassword } from '../Views/edit-user-password/edit-user-password';
import { AdminPanel } from '../Views/admin/admin-panel/admin-panel';
import { Events } from '../Views/admin/events/events';
import { BlockedUsers } from '../Views/admin/blocked-users/blocked-users';
import { Tickets } from '../Views/admin/tickets/tickets';
import { Users } from '../Views/admin/users/users';
import { Dashbord } from '../Views/admin/dashbord/dashbord';

export const routes: Routes = [
  { path: '', component: Home },
  { path: 'login-user', component: LoginUser },
  { path: 'register-user', component: RegisterUser },
  { path: 'login-callback', component: LoginCallback },
  { path: 'seed-database', component: SeedDatabase },
  { path: 'get-events', component: GetEvents },
  { path: 'sub-event-details/:id', component: SubEventDetails },
  { path: 'payment-status', component: PaymentStatus },
  { path: 'search-and-import-events', component: SearchAndImportEvents },
  { path: 'user-tickets', component: UserTickets },
  { path: 'edit-user', component: EditUser },
  { path: 'edit-user-email', component: EditUserEmail },
  { path: 'edit-user-password', component: EditUserPassword },
  { path: 'admin-panel', component: AdminPanel, children:
    [
    { path: '', component: Dashbord },
    { path: 'events', component: Events},
    { path: 'blocked-users', component: BlockedUsers },
    { path: 'tickets', component: Tickets },
    { path: 'users', component: Users },
    ]},
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
