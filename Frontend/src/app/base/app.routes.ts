import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
// import { CreateEventComponent } from '../Views/create-event/create-event.component';
import { Home } from '../Views/home/home';



export const routes: Routes = [
    { path: '', component: Home },
    // { path: 'create-event', component: CreateEventComponent },

];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
