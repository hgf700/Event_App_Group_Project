import { Component, OnInit, ChangeDetectorRef , signal} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { LayoutService } from '../../Services/LayoutService';
import { getCurrentUserDto } from '../../Dto/getCurrentUserDto';
import { EventsNavigationService }from '../../RootingServices/EventsNavigationService'
import { UserNavigationService }from '../../RootingServices/UserNavigationService'

@Component({
  selector: 'app-login-callback',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './login-callback.html',
  styleUrl: './login-callback.css',
})
export class LoginCallback implements OnInit {
  loading = false;
  currentUser!: getCurrentUserDto;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private userService: UserService,
    private layoutService: LayoutService,
    private eventsNavigtionService: EventsNavigationService,
    private userNavigationService: UserNavigationService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.generateJWT();
    this.getCurrentUser();
  }

  generateJWT(){
    const tokenFromUrl = this.route.snapshot.queryParamMap.get('jwt');
    
    const tokenFromStorage = localStorage.getItem('jwt');

    console.log({
      tokenFromUrl,
      tokenFromStorage,
    });

    if (!tokenFromUrl && !tokenFromStorage) {
      console.error('Brak tokena – użytkownik niezalogowany');
      return;
    }
  }

  getCurrentUser() {
    this.loading = true;
    this.userService.getCurrentUserEmail().subscribe({
      next: (data) => {
        this.currentUser = data;
        this.loading = false;
        this.layoutService.setUserEmail(data.email);
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się getCurrentUserEmail');
      },
    });
  }

  adminView() {
    this.eventsNavigtionService.adminPanel()
  }

  eventsView() {
    this.eventsNavigtionService.goToEvents()
  }

  searchAndImportView() {
    this.eventsNavigtionService.searchAndDownloadEvents()
  }

  userBoughtTickets() {
    this.userNavigationService.userBoughtTickets();
  }

  editCurrentUser() {
    this.userNavigationService.editCurrentUser();
  }
}
