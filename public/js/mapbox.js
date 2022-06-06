/* eslint-disable */

export const displayMap = (locations) => {
  mapboxgl.accessToken = 'pk.eyJ1IjoidmFzYW50aGkwNyIsImEiOiJjbDN1Z3Q4MWMxaGV3M2lsdDJ2NXZvcGh6In0.vgcSUyrGOEx6B82_QcAclg';
  var map = new mapboxgl.Map({
    container: 'map',
    style: 'mapbox://styles/vasanthi07/cl3vrtfg4000414pm4sbggaqw',
    scrollZoom: false
    // center: [-118.113491, 34.111745],
    // zoom: 4
  });

  const bounds = new mapboxgl.LngLatBounds();

  locations.forEach(loc => {
    // create marker
    const el = document.createElement('div');
    el.className = 'marker';

    //Add marker
    new mapboxgl.Marker({
      element: el,
      anchor: 'bottom'
    }).setLngLat(loc.coordinates).addTo(map);

    //Add popup
    new mapboxgl.Popup({
      offset: 30
    }).setLngLat(loc.coordinates)
      .setHTML(`<p>Day ${loc.day}: ${loc.description}</p>`)
      .addTo(map);

    //Extend map bounds to include current location
    bounds.extend(loc.coordinates);
  });

  map.fitBounds(bounds, {
    padding: {
      top: 200,
      bottom: 150,
      left: 100,
      right: 100
    }
  });

}
