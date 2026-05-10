import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { getCurrentUserDto } from '../../Dto/getCurrentUserDto';

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
    private cdr: ChangeDetectorRef,
  ) {}

  seedData() {
    this.router.navigate(['/seed-database']);
  }

  eventsView() {
    this.router.navigate(['/get-events']);
  }

  searchAndImportView() {
    this.router.navigate(['/search-and-import-events']);
  }

  ngOnInit(): void {
    const tokenFromUrl = this.route.snapshot.queryParamMap.get('token');
    const tokenFromStorage = localStorage.getItem('jwt');

    if (tokenFromUrl) {
      localStorage.setItem('jwt', tokenFromUrl);
      console.log('JWT zapisany z URL');
    }

    if (!tokenFromUrl && !tokenFromStorage) {
      console.error('Brak tokena – użytkownik niezalogowany');
      return;
    }
  }

  getCurrentUser() {
    this.loading = true;
    this.userService.getCurrentUser().subscribe({
      next: (data) => {
        this.currentUser = data;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się getEvents');
      },
    });
  }
}
