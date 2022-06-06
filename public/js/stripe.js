/* eslint-disable */
import axios from 'axios';
import { showAlert } from './alert';
const stripe = Stripe('pk_test_51L6rWESHRvjgZqXkP9CbEImNOHHMCY8kK4zH9oR1JujfPISjukVgZh8T8T8F7fTzkPUXac8MerMCjx9JR6sX884U002ZVEctip');

export const bookTour = async tourId => {
    try {//1) get the session from the server
        const session = await axios(`http://127.0.0.1:3000/api/v1/bookings/checkout-session/${tourId}`);
        console.log(session);
        // 2) create checkout form + charge credit card}
        await stripe.redirectToCheckout({
            sessionId: session.data.session.id
        });
    } catch (err) {
        console.log(err);
        showAlert('error', err);
    }
}